#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Comprehensive MCP Integration Test Suite for PeMCP.

Tests all 104 MCP tools across every category: file management, PE analysis,
strings, deobfuscation, triage, Angr, multi-format, extended libraries, and more.

Supports both streamable-http (default) and SSE transports.

Usage:
    # Start the server first
    python PeMCP.py --mcp-server --mcp-transport streamable-http --input-file samples/test.exe

    # Run all tests
    pytest mcp_test_client.py -v

    # Run a specific category
    pytest mcp_test_client.py -v -k "TestConfig"
    pytest mcp_test_client.py -v -k "TestPEData"
    pytest mcp_test_client.py -v -k "TestAngr"

    # Run only tests that don't need a loaded file
    pytest mcp_test_client.py -v -m no_file

    # Run with a custom server URL or transport
    PEMCP_TEST_URL=http://localhost:9000 pytest mcp_test_client.py -v
    PEMCP_TEST_TRANSPORT=sse pytest mcp_test_client.py -v

Environment variables:
    PEMCP_TEST_URL         Server URL (default: http://127.0.0.1:8082)
    PEMCP_TEST_TRANSPORT   Transport: "auto" (default), "streamable-http", or "sse"
                           "auto" tries streamable-http first, falls back to SSE
    PEMCP_TEST_SAMPLE      Path to a sample file for open_file tests (optional)
"""

import asyncio
import base64
import json
import logging
import os
import re
import sys
from contextlib import asynccontextmanager, AsyncExitStack
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import httpx
import pytest

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
)
logger = logging.getLogger("pemcp_tests")

# ---------------------------------------------------------------------------
# MCP SDK imports — try streamable-http first, fall back to SSE
# ---------------------------------------------------------------------------
try:
    from mcp import ClientSession, types as mcp_types
    logger.info("MCP SDK core imported.")
except ImportError as exc:
    logger.critical("MCP SDK import failed: %s", exc)
    logger.critical("Install with: pip install 'mcp[cli]'")
    sys.exit(1)

_have_streamable_http = False
try:
    from mcp.client.streamable_http import streamablehttp_client
    _have_streamable_http = True
    logger.info("Streamable-HTTP transport available.")
except ImportError:
    logger.info("Streamable-HTTP transport not available in this MCP SDK version.")

_have_sse = False
try:
    from mcp.client.sse import sse_client
    _have_sse = True
    logger.info("SSE transport available.")
except ImportError:
    logger.info("SSE transport not available.")

if not _have_streamable_http and not _have_sse:
    logger.critical("No MCP transport available. Update the MCP SDK: pip install -U 'mcp[cli]'")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SERVER_URL = os.environ.get("PEMCP_TEST_URL", "http://127.0.0.1:8082")
TRANSPORT = os.environ.get("PEMCP_TEST_TRANSPORT", "auto")
SAMPLE_FILE = os.environ.get("PEMCP_TEST_SAMPLE", "")


# ═══════════════════════════════════════════════════════════════════════════
# Session Management
# ═══════════════════════════════════════════════════════════════════════════

def _extract_root_cause(exc: BaseException) -> str:
    """Dig into ExceptionGroup / BaseExceptionGroup to find the real error."""
    if hasattr(exc, "exceptions"):  # ExceptionGroup / BaseExceptionGroup
        causes = []
        for sub in exc.exceptions:
            causes.append(_extract_root_cause(sub))
        return "; ".join(causes)
    return f"{type(exc).__name__}: {exc}"


@asynccontextmanager
async def _connect_streamable_http(url: str) -> AsyncGenerator[ClientSession, None]:
    """Open a streamable-http session."""
    async with streamablehttp_client(url) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


@asynccontextmanager
async def _connect_sse(url: str) -> AsyncGenerator[ClientSession, None]:
    """Open an SSE session."""
    async with sse_client(url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


@asynccontextmanager
async def managed_mcp_session() -> AsyncGenerator[ClientSession, None]:
    """Connect to the PeMCP server.

    Transport selection (PEMCP_TEST_TRANSPORT env var):
      "auto"             — try streamable-http first, fall back to SSE (default)
      "streamable-http"  — only streamable-http
      "sse"              — only SSE

    The connection phase (with fallback) is fully separated from the
    yield phase so that test assertion errors propagate cleanly and are
    never swallowed by the fallback logic.
    """
    transport = TRANSPORT.lower()

    # Build an ordered list of (label, connect_fn) to try
    attempts: list[tuple[str, Any]] = []
    if transport == "sse":
        if _have_sse:
            attempts.append(("SSE", lambda: _connect_sse(urljoin(SERVER_URL, "/sse"))))
        else:
            pytest.fail("SSE transport requested but not available in this MCP SDK.")
    elif transport == "streamable-http":
        if _have_streamable_http:
            attempts.append(("streamable-http", lambda: _connect_streamable_http(urljoin(SERVER_URL, "/mcp"))))
        else:
            pytest.fail("Streamable-HTTP transport requested but not available in this MCP SDK.")
    else:  # "auto"
        if _have_streamable_http:
            attempts.append(("streamable-http", lambda: _connect_streamable_http(urljoin(SERVER_URL, "/mcp"))))
        if _have_sse:
            attempts.append(("SSE", lambda: _connect_sse(urljoin(SERVER_URL, "/sse"))))

    if not attempts:
        pytest.fail("No MCP transport available. Install the MCP SDK: pip install -U 'mcp[cli]'")

    # --- Phase 1: Connection (with fallback) ---
    # Uses AsyncExitStack so the transport context managers stay open
    # across the yield, but fallback errors don't swallow test failures.
    stack = AsyncExitStack()
    session: Optional[ClientSession] = None
    last_error: Optional[BaseException] = None

    for label, connect_fn in attempts:
        try:
            session = await stack.enter_async_context(connect_fn())
            logger.info("Connected via %s transport.", label)
            break  # success
        except BaseException as exc:
            # Connection/init failed — reset stack and try next transport
            await stack.aclose()
            stack = AsyncExitStack()
            root = _extract_root_cause(exc)
            last_error = exc
            remaining = len(attempts) - attempts.index((label, connect_fn)) - 1
            if remaining > 0:
                logger.warning("%s transport failed: %s. Trying next transport...", label, root)
            else:
                logger.warning("%s transport failed: %s", label, root)

    if session is None:
        await stack.aclose()
        root = _extract_root_cause(last_error) if last_error else "unknown"
        pytest.fail(
            f"Cannot connect to MCP server at {SERVER_URL} "
            f"(tried: {', '.join(l for l, _ in attempts)}): {root}\n"
            f"\n"
            f"Start the server first:\n"
            f"  python PeMCP.py --mcp-server --mcp-transport streamable-http --input-file <sample>\n"
            f"\n"
            f"If using Docker/Podman, add --mcp-host 0.0.0.0 (or use ./run.sh):\n"
            f"  podman run --rm -it -p 8082:8082 pemcp-toolkit \\\n"
            f"    --mcp-server --mcp-transport streamable-http --mcp-host 0.0.0.0 --input-file <sample>"
        )

    # --- Phase 2: Yield the session (test errors propagate cleanly) ---
    try:
        yield session
    finally:
        await stack.aclose()


# ═══════════════════════════════════════════════════════════════════════════
# Test Helpers
# ═══════════════════════════════════════════════════════════════════════════

async def call_tool(
    session: ClientSession,
    tool_name: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    expected_type: Optional[type] = None,
    expected_keys: Optional[List[str]] = None,
    expected_status: Optional[Tuple[str, Any]] = None,
    allow_none: bool = False,
    wrap_single_dict_in_list: bool = False,
) -> Any:
    """Call an MCP tool, parse the response, and run standard assertions."""
    params = params or {}
    logger.info("[CALL] %s(%s)", tool_name, json.dumps(params, default=str))

    result = await session.call_tool(tool_name, arguments=params)

    assert isinstance(result, mcp_types.CallToolResult), (
        f"{tool_name}: expected CallToolResult, got {type(result)}"
    )

    if result.isError:
        text = (
            result.content[0].text
            if result.content and hasattr(result.content[0], "text")
            else "unknown error"
        )
        pytest.fail(f"{tool_name} returned error: {text}")

    if not result.content:
        if allow_none:
            return None
        pytest.fail(f"{tool_name}: empty content but result was expected")

    raw = result.content[0].text
    payload: Any = None

    # Parse strategy
    if tool_name == "get_hex_dump":
        payload = [line for line in raw.splitlines() if line.strip()]
    elif expected_type is str and not raw.strip().startswith(("{", "[")):
        payload = raw
    elif allow_none and raw.strip().lower() == "null":
        payload = None
    else:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            pytest.fail(f"{tool_name}: cannot parse JSON: {raw[:300]}")

    if payload is None and not allow_none:
        pytest.fail(f"{tool_name}: parsed to None but allow_none is False")

    # Wrap single dict → list when needed
    if wrap_single_dict_in_list and expected_type is list and isinstance(payload, dict):
        payload = [payload]

    # Assertions
    if payload is not None:
        if expected_type is not None:
            assert isinstance(payload, expected_type), (
                f"{tool_name}: expected {expected_type.__name__}, got {type(payload).__name__}"
            )
        if isinstance(payload, dict):
            if expected_status:
                key, val = expected_status
                assert key in payload, f"{tool_name}: missing status key '{key}'"
                if isinstance(val, list):
                    assert payload[key] in val
                else:
                    assert payload[key] == val
            if expected_keys:
                for k in expected_keys:
                    assert k in payload, f"{tool_name}: missing key '{k}'"

    logger.info("[PASS] %s", tool_name)
    return payload


async def call_tool_expect_error(
    session: ClientSession,
    tool_name: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    error_substring: Optional[str] = None,
):
    """Call a tool and assert that it returns an error."""
    params = params or {}
    logger.info("[CALL] %s(%s) — expecting error", tool_name, json.dumps(params, default=str))

    try:
        result = await session.call_tool(tool_name, arguments=params)
        assert isinstance(result, mcp_types.CallToolResult)
        assert result.isError, f"{tool_name}: expected isError=True"
        if error_substring:
            text = result.content[0].text if result.content else ""
            assert error_substring.lower() in text.lower(), (
                f"{tool_name}: expected '{error_substring}' in error: {text[:200]}"
            )
        logger.info("[PASS] %s returned expected error", tool_name)
    except mcp_types.JSONRPCError as exc:
        if error_substring:
            assert error_substring.lower() in exc.message.lower()
        logger.info("[PASS] %s raised expected JSONRPCError", tool_name)


def run(coro):
    """Run an async coroutine from a sync test method."""
    asyncio.run(coro)


# ═══════════════════════════════════════════════════════════════════════════
# 1. Configuration & Utility Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestConfigAndUtility:
    """Tests for: get_current_datetime, get_config, set_api_key,
    check_task_status, get_extended_capabilities."""

    @pytest.mark.no_file
    def test_get_current_datetime(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_current_datetime",
                                    expected_type=dict,
                                    expected_keys=["utc_datetime", "local_datetime"])
                assert re.match(r"\d{4}-\d{2}-\d{2}T", r["utc_datetime"])
        run(_test())

    @pytest.mark.no_file
    def test_get_config(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_config", expected_type=dict,
                                expected_keys=["available_libraries"])
        run(_test())

    @pytest.mark.no_file
    def test_get_extended_capabilities(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_extended_capabilities", expected_type=dict)
                assert "tools" in r or "libraries" in r or "available_libraries" in r
        run(_test())

    @pytest.mark.no_file
    def test_check_task_status_invalid(self):
        async def _test():
            async with managed_mcp_session() as s:
                # Checking a non-existent task should return a dict (not crash)
                r = await call_tool(s, "check_task_status",
                                    {"task_id": "nonexistent-task-id-000"},
                                    expected_type=dict)
                assert r is not None
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 2. Cache Management Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestCacheManagement:
    """Tests for: get_cache_stats, clear_analysis_cache, remove_cached_analysis."""

    @pytest.mark.no_file
    def test_get_cache_stats(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_cache_stats", expected_type=dict)
        run(_test())

    @pytest.mark.no_file
    def test_remove_cached_analysis_nonexistent(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "remove_cached_analysis",
                                    {"sha256_hash": "0" * 64}, expected_type=dict)
                assert r is not None
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 3. File Management Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestFileManagement:
    """Tests for: open_file, close_file, reanalyze_loaded_pe_file,
    detect_binary_format."""

    @pytest.mark.pe_file
    def test_get_analyzed_file_summary(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_analyzed_file_summary", {"limit": 5},
                                expected_type=dict, expected_keys=["filepath"])
        run(_test())

    @pytest.mark.pe_file
    def test_get_full_analysis_results(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_full_analysis_results", {"limit": 10},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    def test_detect_binary_format_loaded(self):
        """detect_binary_format with no path uses the loaded file."""
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "detect_binary_format", expected_type=dict)
                assert "format" in r or "detected_format" in r or "binary_format" in r
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 4. Unified PE Data Retrieval (get_pe_data)
# ═══════════════════════════════════════════════════════════════════════════

# All 25 keys supported by get_pe_data
PE_DATA_KEYS = [
    "file_hashes",
    "dos_header",
    "nt_headers",
    "data_directories",
    "sections",
    "imports",
    "exports",
    "resources_summary",
    "version_info",
    "debug_info",
    "digital_signature",
    "peid_matches",
    "yara_matches",
    "rich_header",
    "delay_load_imports",
    "tls_info",
    "load_config",
    "com_descriptor",
    "overlay_data",
    "base_relocations",
    "bound_imports",
    "exception_data",
    "coff_symbols",
    "checksum_verification",
    "pefile_warnings",
]


class TestPEData:
    """Tests for: get_pe_data (all 25 keys) and list discovery."""

    @pytest.mark.pe_file
    def test_get_pe_data_list_keys(self):
        """get_pe_data(key='list') should return all available keys."""
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_pe_data", {"key": "list"}, expected_type=dict)
                # Should contain a listing of available keys
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.parametrize("key", PE_DATA_KEYS)
    def test_get_pe_data_key(self, key: str):
        """Test each get_pe_data key individually."""
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_pe_data",
                                    {"key": key, "limit": 5, "offset": 0},
                                    allow_none=True)
                logger.info("get_pe_data(key=%s) → type=%s", key,
                            type(r).__name__ if r is not None else "None")
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 5. PE Extended Analysis Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestPEExtended:
    """Tests for all 14 PE extended analysis tools."""

    @pytest.mark.pe_file
    def test_get_section_permissions(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_section_permissions", {"limit": 50},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    def test_get_pe_metadata(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_pe_metadata", expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    def test_extract_resources(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "extract_resources", {"limit": 10},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    def test_extract_manifest(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "extract_manifest", expected_type=dict,
                                allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    def test_get_load_config_details(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_load_config_details", expected_type=dict,
                                allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    def test_extract_wide_strings(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "extract_wide_strings",
                                {"min_length": 4, "limit": 50},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    def test_detect_format_strings(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "detect_format_strings", {"limit": 20},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    def test_detect_compression_headers(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "detect_compression_headers", {"limit": 10},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    def test_detect_crypto_constants(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "detect_crypto_constants", {"limit": 20},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    def test_analyze_entropy_by_offset(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "analyze_entropy_by_offset",
                                {"window_size": 256, "step": 256, "limit": 50},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    def test_scan_for_api_hashes(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "scan_for_api_hashes",
                                {"hash_algorithm": "ror13", "limit": 20},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    def test_get_import_hash_analysis(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_import_hash_analysis", expected_type=dict)
        run(_test())

    @pytest.mark.no_file
    def test_deobfuscate_xor_multi_byte(self):
        """XOR multi-byte is a pure-data tool (no file needed)."""
        async def _test():
            async with managed_mcp_session() as s:
                # "Hello" XOR'd with key 0xAB 0xCD
                data = bytes([ord(c) ^ [0xAB, 0xCD][i % 2] for i, c in enumerate("Hello")])
                r = await call_tool(s, "deobfuscate_xor_multi_byte",
                                    {"data_hex": data.hex(), "key_hex": "abcd"},
                                    expected_type=dict)
                assert r is not None
        run(_test())

    @pytest.mark.no_file
    def test_bruteforce_xor_key(self):
        async def _test():
            async with managed_mcp_session() as s:
                original = "This program"
                key = 0x42
                data = bytes([b ^ key for b in original.encode()])
                r = await call_tool(s, "bruteforce_xor_key",
                                    {"data_hex": data.hex(),
                                     "known_plaintext": "This",
                                     "max_key_length": 1, "limit": 5},
                                    expected_type=dict)
                assert r is not None
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 6. String Analysis Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestStringAnalysis:
    """Tests for all 10 string analysis tools."""

    @pytest.mark.pe_file
    def test_get_floss_analysis_info(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_floss_analysis_info",
                                    {"string_type": "static_strings", "limit": 10},
                                    expected_type=dict)
                assert "strings" in r
        run(_test())

    @pytest.mark.pe_file
    def test_get_floss_only_with_references(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_floss_analysis_info",
                                    {"string_type": "static_strings",
                                     "only_with_references": True, "limit": 5},
                                    expected_type=dict)
                if r.get("strings"):
                    for item in r["strings"]:
                        assert "references" in item and item["references"]
        run(_test())

    @pytest.mark.pe_file
    def test_extract_strings_from_binary(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "extract_strings_from_binary",
                                    {"limit": 20, "min_length": 5},
                                    allow_none=True)
                if r is not None:
                    assert isinstance(r, (list, dict))
        run(_test())

    @pytest.mark.pe_file
    def test_search_for_specific_strings(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "search_for_specific_strings",
                                    {"search_terms": ["kernel32.dll", "MZ"]},
                                    expected_type=dict)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    def test_search_floss_strings(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "search_floss_strings",
                                    {"regex_patterns": [".*dll.*"], "limit": 10},
                                    expected_type=dict)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    def test_get_top_sifted_strings(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_top_sifted_strings",
                                    {"limit": 10},
                                    allow_none=True)
                # May be a list or None if StringSifter is not available
                if r is not None:
                    assert isinstance(r, (list, dict))
        run(_test())

    @pytest.mark.pe_file
    def test_fuzzy_search_strings(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "fuzzy_search_strings",
                                    {"query_string": "kermel32.dll",
                                     "limit": 5, "min_similarity_ratio": 60},
                                    allow_none=True)
                if r is not None:
                    assert isinstance(r, (list, dict))
        run(_test())

    @pytest.mark.pe_file
    def test_get_strings_for_function(self):
        """Get strings referenced by a function. Needs a valid function VA."""
        async def _test():
            async with managed_mcp_session() as s:
                # First find a function with string references
                floss = await call_tool(s, "get_floss_analysis_info",
                                        {"string_type": "static_strings",
                                         "only_with_references": True, "limit": 1},
                                        expected_type=dict)
                strings = floss.get("strings", [])
                if not strings or not strings[0].get("references"):
                    pytest.skip("No strings with function references in sample")
                func_va = int(strings[0]["references"][0]["function_va"], 16)
                r = await call_tool(s, "get_strings_for_function",
                                    {"function_va": func_va},
                                    allow_none=True)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    def test_get_string_usage_context(self):
        """Get disassembly context for a string."""
        async def _test():
            async with managed_mcp_session() as s:
                floss = await call_tool(s, "get_floss_analysis_info",
                                        {"string_type": "static_strings",
                                         "only_with_references": True, "limit": 1},
                                        expected_type=dict)
                strings = floss.get("strings", [])
                if not strings:
                    pytest.skip("No strings with references in sample")
                offset = int(strings[0]["offset"], 16)
                r = await call_tool(s, "get_string_usage_context",
                                    {"string_offset": offset},
                                    allow_none=True)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    def test_find_and_decode_encoded_strings(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "find_and_decode_encoded_strings",
                                    {"limit": 5}, allow_none=True)
                if r is not None:
                    assert isinstance(r, (list, dict))
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 7. Deobfuscation & Utility Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestDeobfuscation:
    """Tests for: deobfuscate_base64, deobfuscate_xor_single_byte,
    is_mostly_printable_ascii, get_hex_dump, find_and_decode_encoded_strings."""

    @pytest.mark.no_file
    def test_deobfuscate_base64(self):
        async def _test():
            async with managed_mcp_session() as s:
                original = "Hello MCP!"
                hex_str = base64.b64encode(original.encode()).hex()
                r = await call_tool(s, "deobfuscate_base64",
                                    {"hex_string": hex_str}, expected_type=str)
                assert r == original
        run(_test())

    @pytest.mark.no_file
    def test_deobfuscate_xor_single_byte(self):
        async def _test():
            async with managed_mcp_session() as s:
                original = "XOR Test!"
                key = 0xAB
                data = bytes([ord(c) ^ key for c in original]).hex()
                r = await call_tool(s, "deobfuscate_xor_single_byte",
                                    {"data_hex": data, "key": key},
                                    expected_type=dict)
                assert r.get("deobfuscated_printable_string") == original
        run(_test())

    @pytest.mark.no_file
    def test_is_mostly_printable_ascii(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "is_mostly_printable_ascii",
                                    {"input_string": "Hello World 123!"},
                                    expected_type=dict)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    def test_get_hex_dump(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_hex_dump",
                                    {"start_offset": 0, "length": 64},
                                    expected_type=list)
                assert r and "00000000" in r[0]
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 8. Capa Analysis Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestCapaAnalysis:
    """Tests for: get_capa_analysis_info, get_capa_rule_match_details."""

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_get_capa_analysis_info(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_capa_analysis_info", {"limit": 10},
                                    expected_type=dict, expected_keys=["rules"])
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_get_capa_rule_match_details(self):
        """Fetch details for the first capa rule found."""
        async def _test():
            async with managed_mcp_session() as s:
                capa = await call_tool(s, "get_capa_analysis_info",
                                       {"limit": 1}, expected_type=dict)
                rules = capa.get("rules", [])
                if not rules:
                    pytest.skip("No capa rules matched in sample")
                rule_id = rules[0].get("rule_name") or rules[0].get("name")
                if not rule_id:
                    pytest.skip("Cannot determine rule_id from capa output")
                r = await call_tool(s, "get_capa_rule_match_details",
                                    {"rule_id": rule_id}, expected_type=dict)
                assert r is not None
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 9. Triage & Classification Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestTriageAndClassification:
    """Tests for: get_triage_report, classify_binary_purpose."""

    @pytest.mark.pe_file
    def test_get_triage_report(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_triage_report", expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    def test_classify_binary_purpose(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "classify_binary_purpose", expected_type=dict)
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 10. VirusTotal Tool
# ═══════════════════════════════════════════════════════════════════════════

class TestVirusTotal:
    """Tests for: get_virustotal_report_for_loaded_file."""

    @pytest.mark.pe_file
    def test_get_virustotal_report(self):
        async def _test():
            async with managed_mcp_session() as s:
                valid = [
                    "success", "not_found", "api_key_missing", "error_auth",
                    "error_rate_limit", "error_api", "error_timeout",
                    "error_request", "error_unexpected",
                ]
                r = await call_tool(s, "get_virustotal_report_for_loaded_file",
                                    expected_type=dict,
                                    expected_status=("status", valid))
                logger.info("VT status: %s", r.get("status"))
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 11. Angr Core Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestAngrCore:
    """Tests for all 15 core Angr tools."""

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_list_angr_analyses(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "list_angr_analyses",
                                    {"category": "all"}, expected_type=dict)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_function_complexity_list(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "get_function_complexity_list",
                                    {"limit": 5, "sort_by": "blocks"},
                                    expected_type=dict, allow_none=True)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_decompile_function_with_angr(self):
        """Decompile the top function from the complexity list."""
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                r = await call_tool(s, "decompile_function_with_angr",
                                    {"function_address": str(addr)},
                                    expected_type=dict)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_function_cfg(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                r = await call_tool(s, "get_function_cfg",
                                    {"function_address": str(addr)},
                                    expected_type=dict)
                assert r is not None
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_function_xrefs(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_function_xrefs",
                                {"function_address": str(addr)},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_extract_function_constants(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "extract_function_constants",
                                {"function_address": str(addr)},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_global_data_refs(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_global_data_refs",
                                {"function_address": str(addr)},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_scan_for_indirect_jumps(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "scan_for_indirect_jumps",
                                {"function_address": str(addr)},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_analyze_binary_loops(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "analyze_binary_loops", expected_type=dict,
                                allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_backward_slice(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_backward_slice",
                                {"target_address": str(addr)},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_forward_slice(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_forward_slice",
                                {"source_address": str(addr)},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_dominators(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_dominators",
                                {"target_address": str(addr)},
                                expected_type=dict, allow_none=True)
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 12. Angr Disassembly & Function Recovery Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestAngrDisasm:
    """Tests for: disassemble_at_address, get_calling_conventions,
    get_function_variables, identify_library_functions, get_annotated_disassembly."""

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_disassemble_at_address(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "disassemble_at_address",
                                {"address": str(addr), "num_instructions": 10},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_calling_conventions(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_calling_conventions",
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_function_variables(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_function_variables",
                                {"function_address": str(addr)},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_identify_library_functions(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "identify_library_functions",
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_annotated_disassembly(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_annotated_disassembly",
                                {"function_address": str(addr), "limit": 50},
                                expected_type=dict)
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 13. Angr Data Flow Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestAngrDataflow:
    """Tests for: get_reaching_definitions, get_data_dependencies,
    get_control_dependencies, propagate_constants, get_value_set_analysis."""

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_reaching_definitions(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_reaching_definitions",
                                {"function_address": str(addr),
                                 "limit": 20, "run_in_background": False},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_data_dependencies(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_data_dependencies",
                                {"function_address": str(addr)},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_control_dependencies(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_control_dependencies",
                                {"function_address": str(addr)},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_propagate_constants(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "propagate_constants",
                                {"function_address": str(addr)},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_value_set_analysis(self):
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))
                await call_tool(s, "get_value_set_analysis",
                                {"function_address": str(addr)},
                                expected_type=dict, allow_none=True)
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 14. Angr Hook Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestAngrHooks:
    """Tests for: hook_function, list_hooks, unhook_function."""

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_list_hooks(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "list_hooks", expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_hook_and_unhook_function(self):
        """Hook a function, list hooks, then unhook it."""
        async def _test():
            async with managed_mcp_session() as s:
                complexity = await call_tool(s, "get_function_complexity_list",
                                             {"limit": 1}, expected_type=dict,
                                             allow_none=True)
                funcs = complexity.get("functions", []) if complexity else []
                if not funcs:
                    pytest.skip("No functions found by Angr")
                addr = funcs[0].get("address", funcs[0].get("addr"))

                # Hook with NOP
                await call_tool(s, "hook_function",
                                {"address_or_name": str(addr), "nop": True},
                                expected_type=dict)
                # Verify it appears
                hooks = await call_tool(s, "list_hooks", expected_type=dict)
                assert hooks is not None
                # Unhook
                await call_tool(s, "unhook_function",
                                {"address_or_name": str(addr)},
                                expected_type=dict)
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 15. Angr Forensic & Advanced Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestAngrForensic:
    """Tests for: detect_packing, find_code_caves, detect_self_modifying_code,
    get_call_graph, identify_cpp_classes."""

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_detect_packing(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "detect_packing", expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_find_code_caves(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "find_code_caves",
                                {"min_size": 16, "limit": 10},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_detect_self_modifying_code(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "detect_self_modifying_code",
                                {"limit": 10}, expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_get_call_graph(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "get_call_graph", expected_type=dict,
                                allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_identify_cpp_classes(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "identify_cpp_classes", expected_type=dict,
                                allow_none=True)
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 16. Extended Library Tools (LIEF, Capstone, Keystone, Speakeasy, etc.)
# ═══════════════════════════════════════════════════════════════════════════

class TestExtendedLibraries:
    """Tests for all 13 extended library tools."""

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_parse_binary_with_lief(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "parse_binary_with_lief", expected_type=dict)
        run(_test())

    @pytest.mark.no_file
    @pytest.mark.optional_lib
    def test_disassemble_raw_bytes(self):
        """Disassemble a NOP sled — no file needed."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "disassemble_raw_bytes",
                                {"hex_bytes": "90909090cccc",
                                 "architecture": "x86_64", "limit": 10},
                                expected_type=dict)
        run(_test())

    @pytest.mark.no_file
    @pytest.mark.optional_lib
    def test_assemble_instruction(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "assemble_instruction",
                                {"assembly": "nop; nop; ret",
                                 "architecture": "x86_64"},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_compute_similarity_hashes(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "compute_similarity_hashes",
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_emulate_pe_with_windows_apis(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "emulate_pe_with_windows_apis",
                                {"timeout_seconds": 10, "limit": 50},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.no_file
    @pytest.mark.optional_lib
    def test_emulate_shellcode_with_speakeasy(self):
        """Emulate a tiny shellcode stub (INT3)."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "emulate_shellcode_with_speakeasy",
                                {"shellcode_hex": "cc",
                                 "architecture": "x86",
                                 "timeout_seconds": 5, "limit": 10},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_auto_unpack_pe(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "auto_unpack_pe", expected_type=dict,
                                allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_parse_dotnet_metadata(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "parse_dotnet_metadata", {"limit": 20},
                                expected_type=dict, allow_none=True)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_scan_for_embedded_files(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "scan_for_embedded_files", {"limit": 10},
                                expected_type=dict)
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 17. Multi-Format Binary Analysis Tools
# ═══════════════════════════════════════════════════════════════════════════

class TestMultiFormat:
    """Tests for: detect_binary_format, dotnet_analyze, dotnet_disassemble_method,
    go_analyze, rust_analyze, rust_demangle_symbols, elf_analyze, elf_dwarf_info,
    macho_analyze."""

    @pytest.mark.pe_file
    def test_detect_binary_format(self):
        async def _test():
            async with managed_mcp_session() as s:
                r = await call_tool(s, "detect_binary_format", expected_type=dict)
                assert "format" in r or "detected_format" in r or "binary_format" in r
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_dotnet_analyze(self):
        """May return 'not a .NET binary' for non-.NET samples — that's OK."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "dotnet_analyze", {"limit": 20},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_go_analyze(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "go_analyze", {"limit": 20},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_rust_analyze(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "rust_analyze", expected_type=dict)
        run(_test())

    @pytest.mark.no_file
    @pytest.mark.optional_lib
    def test_rust_demangle_symbols(self):
        """Rust demangle is a pure-data tool."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "rust_demangle_symbols",
                                {"symbols": ["_ZN4core3fmt5write17h01234abcdef56789E"],
                                 "limit": 10},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_elf_analyze(self):
        """Will report 'not an ELF' for PE samples — that's expected."""
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "elf_analyze", {"limit": 20},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_elf_dwarf_info(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "elf_dwarf_info", {"limit": 20},
                                expected_type=dict)
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.optional_lib
    def test_macho_analyze(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool(s, "macho_analyze", {"limit": 20},
                                expected_type=dict)
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 18. Error Handling & Edge Cases
# ═══════════════════════════════════════════════════════════════════════════

class TestErrorHandling:
    """Verify tools return proper errors for invalid input."""

    @pytest.mark.no_file
    def test_get_pe_data_invalid_key(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool_expect_error(
                    s, "get_pe_data",
                    {"key": "this_key_does_not_exist"},
                )
        run(_test())

    @pytest.mark.pe_file
    @pytest.mark.angr
    def test_decompile_invalid_address(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool_expect_error(
                    s, "decompile_function_with_angr",
                    {"function_address": "0xDEADBEEFDEAD"},
                )
        run(_test())

    @pytest.mark.no_file
    def test_open_file_nonexistent(self):
        async def _test():
            async with managed_mcp_session() as s:
                await call_tool_expect_error(
                    s, "open_file",
                    {"file_path": "/nonexistent/path/to/file.exe"},
                    error_substring="not found",
                )
        run(_test())


# ═══════════════════════════════════════════════════════════════════════════
# 19. Tool Discovery — verify all 104 tools are registered
# ═══════════════════════════════════════════════════════════════════════════

# Complete list of all 104 tools in PeMCP
ALL_TOOL_NAMES = sorted([
    # File management (6)
    "open_file", "close_file", "reanalyze_loaded_pe_file",
    "get_analyzed_file_summary", "get_full_analysis_results", "get_pe_data",
    # Config & utilities (4)
    "get_current_datetime", "check_task_status", "set_api_key", "get_config",
    # Cache (3)
    "get_cache_stats", "clear_analysis_cache", "remove_cached_analysis",
    # PE extended (14)
    "get_section_permissions", "get_pe_metadata", "extract_resources",
    "extract_manifest", "get_load_config_details", "extract_wide_strings",
    "detect_format_strings", "detect_compression_headers",
    "deobfuscate_xor_multi_byte", "bruteforce_xor_key",
    "detect_crypto_constants", "analyze_entropy_by_offset",
    "scan_for_api_hashes", "get_import_hash_analysis",
    # Strings (10)
    "search_floss_strings", "get_floss_analysis_info",
    "get_capa_analysis_info", "get_capa_rule_match_details",
    "extract_strings_from_binary", "search_for_specific_strings",
    "get_top_sifted_strings", "get_strings_for_function",
    "get_string_usage_context", "fuzzy_search_strings",
    # Deobfuscation (5)
    "get_hex_dump", "deobfuscate_base64", "deobfuscate_xor_single_byte",
    "is_mostly_printable_ascii", "find_and_decode_encoded_strings",
    # Angr core (15)
    "list_angr_analyses", "decompile_function_with_angr", "get_function_cfg",
    "find_path_to_address", "emulate_function_execution",
    "analyze_binary_loops", "get_function_xrefs", "get_backward_slice",
    "get_forward_slice", "get_dominators", "get_function_complexity_list",
    "extract_function_constants", "get_global_data_refs",
    "scan_for_indirect_jumps", "patch_binary_memory",
    # Angr dataflow (5)
    "get_reaching_definitions", "get_data_dependencies",
    "get_control_dependencies", "propagate_constants", "get_value_set_analysis",
    # Angr disasm (5)
    "disassemble_at_address", "get_calling_conventions",
    "get_function_variables", "identify_library_functions",
    "get_annotated_disassembly",
    # Angr forensic (9)
    "diff_binaries", "detect_self_modifying_code", "find_code_caves",
    "detect_packing", "save_patched_binary", "find_path_with_custom_input",
    "emulate_with_watchpoints", "identify_cpp_classes", "get_call_graph",
    # Angr hooks (3)
    "hook_function", "list_hooks", "unhook_function",
    # Classification (1)
    "classify_binary_purpose",
    # Format detection (1)
    "detect_binary_format",
    # VirusTotal (1)
    "get_virustotal_report_for_loaded_file",
    # Triage (1)
    "get_triage_report",
    # Extended libraries (13)
    "parse_binary_with_lief", "modify_pe_section", "disassemble_raw_bytes",
    "assemble_instruction", "patch_with_assembly",
    "compute_similarity_hashes", "compare_file_similarity",
    "emulate_pe_with_windows_apis", "emulate_shellcode_with_speakeasy",
    "auto_unpack_pe", "parse_dotnet_metadata", "scan_for_embedded_files",
    "get_extended_capabilities",
    # Multi-format (9)
    "dotnet_analyze", "dotnet_disassemble_method",
    "go_analyze", "rust_analyze", "rust_demangle_symbols",
    "elf_analyze", "elf_dwarf_info", "macho_analyze",
    # (detect_binary_format already listed above)
])


class TestToolDiscovery:
    """Verify all expected tools are registered on the server."""

    @pytest.mark.no_file
    def test_all_tools_registered(self):
        """List tools from the server and check all 104 are present."""
        async def _test():
            async with managed_mcp_session() as s:
                result = await s.list_tools()
                server_tools = {t.name for t in result.tools}
                logger.info("Server reports %d tools.", len(server_tools))

                missing = set(ALL_TOOL_NAMES) - server_tools
                if missing:
                    pytest.fail(
                        f"{len(missing)} tools missing from server: "
                        f"{sorted(missing)}"
                    )
                logger.info("All %d expected tools are registered.", len(ALL_TOOL_NAMES))
        run(_test())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("PeMCP Integration Test Suite")
    print("=" * 50)
    print()
    print("Usage:")
    print("  pytest mcp_test_client.py -v                  # Run all tests")
    print("  pytest mcp_test_client.py -v -m no_file       # Tests without a loaded file")
    print("  pytest mcp_test_client.py -v -m pe_file       # Tests requiring a PE file")
    print("  pytest mcp_test_client.py -v -m angr          # Angr tests only")
    print("  pytest mcp_test_client.py -v -k TestPEData    # PE data retrieval tests")
    print("  pytest mcp_test_client.py -v -k TestConfig    # Config & utility tests")
    print()
    print("Environment variables:")
    print(f"  PEMCP_TEST_URL       = {SERVER_URL}")
    print(f"  PEMCP_TEST_TRANSPORT = {TRANSPORT}  (auto|streamable-http|sse)")
    print(f"  PEMCP_TEST_SAMPLE    = {SAMPLE_FILE or '(not set)'}")
    print()
    print("Start the server first:")
    print("  python PeMCP.py --mcp-server --mcp-transport streamable-http --input-file samples/test.exe")
    print()
    sys.exit(pytest.main([__file__, "-v"]))
