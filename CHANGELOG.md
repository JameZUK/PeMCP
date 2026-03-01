# Changelog

All notable changes to PeMCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Three malware family identification tools: `identify_malware_family()`, `list_malware_signatures()`, `verify_malware_attribution()` — match binary indicators against a 123-family signature knowledge base (`pemcp/data/malware_signatures.yaml`) for automated malware attribution with confidence scoring.
- `pemcp/constants.py` — pure constants module (no side effects, safe to import anywhere).
- `pemcp/imports.py` — centralised optional library imports and availability flags.
- `pemcp/py.typed` — PEP 561 marker for type checker support.
- SIGTERM graceful shutdown handler in MCP server mode (reuses existing cleanup path).
- New test suites: `test_format_helpers.py` (format detection) and `test_input_helpers.py` (parsing, caching, pagination).
- CI smoke-test job that verifies CLI `--help` and core module imports.
- `CHANGELOG.md` and `docs/CONTRIBUTING.md`.

### Changed
- Split `pemcp/config.py` into three focused modules (`constants.py`, `imports.py`, `config.py`). All existing `from pemcp.config import ...` statements continue to work via re-exports.
- Refactored `pemcp/main.py` from a monolithic 521-line `main()` into 7 focused functions with a `_ResolvedConfig` dataclass.
- Moved gzip compression in `cache.py` `put()` outside the lock to avoid blocking concurrent callers.
- Reduced redundant UTF-8 encoding in `_check_mcp_response_size` truncation loop.
- Removed `_format_helpers.py` from `.coveragerc` omit list (now covered by unit tests).
- Raised CI coverage threshold from 60% to 65%.
- Moved `mcp_test_client.py` to `tests/integration/mcp_test_client.py`.

### Fixed
- Removed duplicate `PEMCP_HOST_SAMPLES` environment variable in `run.sh`.
- Replaced deprecated `asyncio.get_event_loop().run_until_complete()` with `asyncio.run()` in test helper.
- Corrected tool count from 196 to 171 across all documentation (README, SKILL.md, tooling-reference.md, PROJECT_REVIEW.md).

### Renamed
- `.claude/skills/analyze/` → `.claude/skills/pemcp-analyze/`
- `.claude/skills/analyse/` → `.claude/skills/pemcp-analyse/`
