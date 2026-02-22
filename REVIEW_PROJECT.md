# PeMCP Project Review

**Date**: 2026-02-22
**Reviewer**: Claude (automated review)

## Overview

PeMCP is a PE (Portable Executable) file analysis server exposed via the MCP (Model Context Protocol), enabling LLM-powered malware triage workflows. It provides 184+ analysis tools spanning static analysis, emulation, disassembly, string extraction, signature scanning, and binary data transformation.

**Tech stack**: Python 3.10-3.12, MCP protocol, pefile, angr, Binary Refinery, YARA, capa, FLOSS, Speakeasy, Qiling.

**Codebase**: ~24,500 lines of application code (40+ modules), ~4,100 lines of tests (18 modules, 398 tests).

---

## Strengths

### 1. Architecture & Design (Excellent)

- Clean separation of concerns: `config.py` centralises imports/feature flags, `state.py` manages per-session state, `server.py` provides the tool decorator, and `tools_*.py` files register MCP tools.
- `StateProxy` + `contextvars` pattern enables transparent session isolation in HTTP mode without changing tool code.
- Graceful degradation for optional dependencies — any heavy library (angr, capa, FLOSS, etc.) can be absent without breaking the server.

### 2. Security (Strong)

- **Path traversal protection** (`state.py:110-126`): `check_path_allowed()` uses `os.path.realpath()` and `is_relative_to()`, called consistently across tools.
- **ReDoS prevention** (`utils.py:52-109`): Validates pattern length, nested quantifiers, and compilation — plus a 5-second hard timeout as defence-in-depth.
- **Authentication** (`auth.py`): `hmac.compare_digest()` for constant-time token comparison. Proper 401/close responses.
- **API key storage** (`user_config.py`): Config written with `0o600` permissions, masked display in status output.
- **Subprocess safety**: Commands use list-based arguments (not shell strings), avoiding injection.

### 3. Testing & CI (Strong)

- 398 tests across 18 modules with parametrised edge cases, concurrency testing, and mock PE objects.
- CI runs on Python 3.10/3.11/3.12 with a 60% minimum coverage floor.
- Lightweight `requirements-ci.txt` (3 packages) keeps CI fast.
- Ruff linting passes cleanly.

### 4. Docker & Deployment (Excellent)

- Base image pinned by SHA digest for reproducibility.
- Strategic layer ordering puts slow-changing heavy deps first for cache efficiency.
- Isolated virtualenvs for Speakeasy/Unipacker/Qiling (conflicting unicorn versions).
- Pre-populated Qiling rootfs and capa rules at build time.
- Health check endpoint included.

### 5. Documentation (Comprehensive)

- 1,100+ line README with installation guides, tool reference (184 tools categorised), architecture docs, and security section.
- Separate TESTING.md and DEPENDENCIES.md.

---

## Issues & Recommendations

### Issue 1: Duplicated Subprocess Runner Pattern (Medium)

**Location**: `tools_new_libs.py:550`, `tools_new_libs.py:645`, `tools_qiling.py:26`

`_run_speakeasy()`, `_run_unipacker()`, and `_run_qiling()` are nearly identical (~30 lines each) — same create_subprocess_exec/wait_for/timeout/JSON decode pattern. Only the binary path and error prefix differ.

**Recommendation**: Extract a shared `_run_venv_subprocess(python_path, runner_path, cmd, timeout, label)` helper to eliminate ~60 lines of duplication.

### Issue 2: Constant Maps Rebuilt on Every Call (Low)

**Location**: `tools_refinery.py:54-73` and similar refinery tool files

`_ENCODING_MAP` and similar lookup dictionaries are defined inside function bodies, meaning they're reconstructed on every invocation.

**Recommendation**: Move constant maps to module-level scope for clarity and minor performance improvement.

### Issue 3: Hardcoded Virtualenv Paths (Low)

**Location**: `config.py:374,406,438`

Paths like `/app/speakeasy-venv/bin/python` are hardcoded. Validated before use but not configurable.

**Recommendation**: Allow override via environment variables (e.g., `PEMCP_SPEAKEASY_VENV`) for non-Docker deployments.

### Issue 4: Silent Cleanup Exception Swallowing (Low)

**Location**: `resources.py:71-74`

`except OSError: pass` silently swallows file removal failures, potentially hiding disk-full or permission errors.

**Recommendation**: Replace with `logger.debug("Cleanup failed for %s: %s", path, e)`.

### Issue 5: Missing Type Hints in Utilities (Low)

**Locations**: `hashing.py:100`, `utils.py:20-40`

Several utility functions lack type annotations.

**Recommendation**: Add type hints for IDE support and self-documentation.

### Issue 6: Dockerfile oscrypto Patch Fragility (Low)

**Location**: `Dockerfile:184-185`

Patches oscrypto from a specific Git commit hash. If the repository or commit becomes unavailable, Docker builds will fail.

**Recommendation**: Vendor the patched file or add a fallback to prevent build breakage.

### Issue 7: Tool Module Test Coverage (Observation)

The tool modules (`tools_pe.py`, `tools_angr.py`, etc.) are excluded from coverage measurement. These are the largest files by line count.

**Recommendation**: Add an optional integration test suite that runs in Docker where all deps are available.

---

## Summary

| Area | Rating | Notes |
|---|---|---|
| Architecture | Excellent | Clean module separation, session isolation, graceful degradation |
| Security | Strong | Path traversal, ReDoS, timing-safe auth, subprocess safety |
| Code Quality | Good | Clean code, consistent patterns; minor duplication |
| Testing | Strong | 398 tests, multi-version CI, coverage enforcement |
| Documentation | Excellent | Comprehensive README, tool reference, testing guide |
| Docker/DevOps | Excellent | Reproducible builds, layer optimisation, health checks |
| Dependencies | Well-managed | Three-tier requirements, graceful optional dep handling |

**Overall**: Well-engineered project with strong security practices and thoughtful architecture. No critical issues found. Main improvement opportunities: reduce subprocess runner duplication, hoist constant maps to module scope, and expand integration test coverage for tool modules.
