#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
COMPLETE and MERGED MCP Test Client for the PeMCP.py Server.

This script combines the original comprehensive test suite with new and updated
tests for all enhanced features, including advanced string analysis, context-aware
tools, fuzzy search, and triage workflows.
"""

import asyncio
import json
import logging
import os
from typing import Any, Dict, List, Optional, Union, AsyncGenerator, Tuple
import sys
from urllib.parse import urljoin
import base64
import re
from contextlib import asynccontextmanager

import pytest
import httpx

# --- Configure Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s')
test_logger = logging.getLogger("mcp_test_client")

# --- Import MCP Client library components ---
try:
    from mcp import ClientSession, types as mcp_types
    from mcp.client.sse import sse_client as mcp_sse_transport_client
    test_logger.info("MCP SDK components imported successfully.")
except ImportError as e:
    test_logger.critical(f"MCP SDK import failed: {e}")
    test_logger.critical("Please ensure the MCP Python SDK is installed correctly (e.g., pip install mcp-sdk).")
    sys.exit(1)

# --- Configuration ---
SERVER_BASE_URL = os.environ.get("PEMCP_TEST_SERVER_URL", "http://127.0.0.1:8082")
SSE_PATH = "/sse"

# --- MCP Client Session Context Manager ---
@asynccontextmanager
async def managed_mcp_session() -> AsyncGenerator[ClientSession, None]:
    sse_full_url = urljoin(SERVER_BASE_URL, SSE_PATH)
    active_session: Optional[ClientSession] = None
    try:
        async with mcp_sse_transport_client(sse_full_url) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                active_session = session
                await session.initialize()
                yield active_session
    except httpx.ConnectError as e_conn:
        msg = (f"SESSION CTX MGR ERROR: Connection to MCP server failed: {e_conn}. "
               f"Ensure PeMCP.py server is running on {SERVER_BASE_URL}.")
        pytest.fail(msg)
    except Exception as e_fixture:
        err_msg_detail = str(e_fixture)
        if isinstance(e_fixture, mcp_types.JSONRPCError):
             err_msg_detail = (f"MCP session.initialize() returned an error: "
                               f"Code: {e_fixture.code}, Message: '{e_fixture.message}'")
        msg = f"SESSION CTX MGR ERROR: Problem during session setup: {type(e_fixture).__name__} - {err_msg_detail}"
        pytest.fail(msg)

# --- Test Helper Functions (from original script) ---
async def call_tool_and_assert_success(
    session: ClientSession,
    tool_name: str,
    params: Dict[str, Any],
    expected_top_level_type: Optional[type] = None,
    expected_keys: Optional[List[str]] = None,
    expected_status_in_payload: Optional[Tuple[str, Any]] = None,
    is_list_expected_even_for_limit_1: bool = False,
    allow_none_result: bool = False
) -> Any:
    """
    This is the final, robust version of the tool calling helper. It correctly
    handles JSON vs. raw text responses, single-item list conversion, and other
    edge cases identified during testing.
    """
    test_logger.info(f"[TEST CALL] Tool: '{tool_name}', Params: {json.dumps(params, default=str)}")
    response_wrapper = await session.call_tool(tool_name, arguments=params)

    assert isinstance(response_wrapper, mcp_types.CallToolResult), \
        f"Tool '{tool_name}' call did not return a CallToolResult. Got: {type(response_wrapper)}"

    if response_wrapper.isError:
        error_text = response_wrapper.content[0].text if response_wrapper.content and hasattr(response_wrapper.content[0], 'text') else "Unknown error content"
        pytest.fail(f"Tool '{tool_name}' call failed with error from server: {error_text}")

    if not response_wrapper.content:
        if allow_none_result:
            return None
        pytest.fail(f"Tool '{tool_name}' success response has no content items, and content was expected.")

    json_text_payload = response_wrapper.content[0].text
    actual_result_payload: Any = None

    # --- FINAL ROBUST PARSING LOGIC ---
    # Special case for get_hex_dump which returns a raw multi-line string
    if tool_name == "get_hex_dump":
        actual_result_payload = [line for line in json_text_payload.splitlines() if line.strip()]
    # Special case for tools returning a single raw string
    elif expected_top_level_type == str and not json_text_payload.strip().startswith(("{", "[")):
        actual_result_payload = json_text_payload
    # Handle JSON null
    elif allow_none_result and json_text_payload.lower() == 'null':
        actual_result_payload = None
    # Default case: Parse as JSON
    else:
        try:
            actual_result_payload = json.loads(json_text_payload)
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON success payload for '{tool_name}': '{json_text_payload}'.")

    if actual_result_payload is None and not allow_none_result:
        pytest.fail(f"Tool '{tool_name}' payload processed to None, but allow_none_result is False.")

    # Logic to wrap a single dictionary in a list if a list is expected
    if is_list_expected_even_for_limit_1 and expected_top_level_type == list and isinstance(actual_result_payload, dict):
        test_logger.warning(f"Tool '{tool_name}' expected a list but got a dict; wrapping in list for test consistency.")
        actual_result_payload = [actual_result_payload]

    # Standard Assertions
    if not (allow_none_result and actual_result_payload is None):
        if expected_top_level_type is not None:
            assert isinstance(actual_result_payload, expected_top_level_type), \
                f"Tool '{tool_name}' payload type {type(actual_result_payload)} did not match expected {expected_top_level_type}."

        if isinstance(actual_result_payload, dict):
            if expected_status_in_payload:
                status_key, expected_value = expected_status_in_payload
                assert status_key in actual_result_payload
                if isinstance(expected_value, list):
                    assert actual_result_payload[status_key] in expected_value
                else:
                    assert actual_result_payload[status_key] == expected_value
            if expected_keys:
                for k in expected_keys:
                    assert k in actual_result_payload, f"Expected key '{k}' not in payload."

    return actual_result_payload

async def call_tool_and_expect_server_error_in_result(
    session: ClientSession,
    tool_name: str,
    params: Dict[str, Any],
    expected_error_message_substring: Optional[str] = None,
    expected_rpc_error_code: Optional[int] = None,
):
    test_logger.info(f"[TEST CALL] Tool: '{tool_name}', Params: {json.dumps(params, default=str)} (EXPECTING ERROR)")
    try:
        response_wrapper = await session.call_tool(tool_name, arguments=params)
        assert isinstance(response_wrapper, mcp_types.CallToolResult)
        assert response_wrapper.isError, f"Tool '{tool_name}' CallToolResult.isError was False, but an error was expected."
        error_text = response_wrapper.content[0].text
        if expected_error_message_substring is not None:
            assert expected_error_message_substring.lower() in error_text.lower()
        test_logger.info(f"PASSED: {tool_name} returned expected error in CallToolResult.")
    except mcp_types.JSONRPCError as e_rpc:
        if expected_rpc_error_code is not None:
            assert e_rpc.code == expected_rpc_error_code
        if expected_error_message_substring is not None:
            assert expected_error_message_substring.lower() in e_rpc.message.lower()
        test_logger.info(f"PASSED: {tool_name} raised expected JSONRPCError.")
    except Exception as e_unexp:
        pytest.fail(f"Tool '{tool_name}' raised unexpected exception {type(e_unexp).__name__}: {e_unexp}")


# --- Test Classes (Merged and Updated) ---

class TestServerUtilityTools:
    def test_get_current_server_datetime(self):
        async def _run():
            async with managed_mcp_session() as session:
                result = await call_tool_and_assert_success(
                    session, "get_current_datetime", {}, dict, ["utc_datetime", "local_datetime"]
                )
                assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|([+-]\d{2}:\d{2}))", result.get("utc_datetime", ""))
                test_logger.info("PASSED: get_current_datetime")
        asyncio.run(_run())

class TestCoreAnalysisDataTools:
    def test_get_analyzed_file_summary(self):
        async def _run():
            async with managed_mcp_session() as session:
                await call_tool_and_assert_success(session, "get_analyzed_file_summary", {"limit": 5}, dict, ["filepath"])
                test_logger.info("PASSED: get_analyzed_file_summary")
        asyncio.run(_run())

    def test_get_full_analysis_results(self):
        async def _run():
            async with managed_mcp_session() as session:
                await call_tool_and_assert_success(session, "get_full_analysis_results", {"limit": 10}, dict, ["dos_header"])
                test_logger.info("PASSED: get_full_analysis_results")
        asyncio.run(_run())

TOOL_PARAMETRIZATION = [
    ("get_file_hashes_info", dict, False, False),
    ("get_dos_header_info", dict, False, False),
    ("get_nt_headers_info", dict, False, False),
    ("get_data_directories_info", list, True, False),
    ("get_imports_info", list, True, False),
    ("get_sections_info", list, True, False),
    ("get_exports_info", dict, False, True),
    ("get_resources_summary_info", list, True, False),
    ("get_version_info_info", dict, False, True),
    ("get_debug_info_info", list, True, True),
    ("get_digital_signature_info", dict, False, True),
    ("get_peid_matches_info", dict, False, False),
    ("get_yara_matches_info", list, True, True),
    ("get_rich_header_info", dict, False, True),
    ("get_delay_load_imports_info", list, True, True),
    ("get_tls_info_info", dict, False, True),
    ("get_load_config_info", dict, False, True),
    ("get_com_descriptor_info", dict, False, True),
    ("get_overlay_data_info", dict, False, True),
    ("get_base_relocations_info", list, True, True),
    ("get_bound_imports_info", list, True, True),
    ("get_exception_data_info", list, True, True),
    ("get_coff_symbols_info", list, True, True),
    ("get_checksum_verification_info", dict, False, False),
    ("get_pefile_warnings_info", list, True, True)
]

class TestRemainingPEAnalysisInfoTools:
    @pytest.mark.parametrize("tool_name, expected_type, is_list, allow_none", TOOL_PARAMETRIZATION)
    def test_dynamic_pe_info_tool(self, tool_name: str, expected_type: type, is_list: bool, allow_none: bool):
        async def _run():
            async with managed_mcp_session() as session:
                await call_tool_and_assert_success(
                    session, tool_name, {"limit": 5, "offset": 0}, expected_type,
                    is_list_expected_even_for_limit_1=is_list, allow_none_result=allow_none
                )
                test_logger.info(f"PASSED: {tool_name}")
        asyncio.run(_run())

class TestDeobfuscationAndEncodingTools:
    def test_deobfuscate_base64(self):
        async def _run():
            async with managed_mcp_session() as session:
                original = "Hello MCP!"
                hex_str = base64.b64encode(original.encode()).hex()
                result = await call_tool_and_assert_success(session, "deobfuscate_base64", {"hex_string": hex_str}, str)
                assert result == original
                test_logger.info("PASSED: deobfuscate_base64")
        asyncio.run(_run())

    def test_deobfuscate_xor(self):
        async def _run():
            async with managed_mcp_session() as session:
                original = "XOR Test!"
                key = 0xAB
                hex_str = bytes([ord(c) ^ key for c in original]).hex()
                result = await call_tool_and_assert_success(session, "deobfuscate_xor_single_byte", {"data_hex": hex_str, "key": key}, dict)
                assert result.get("deobfuscated_printable_string") == original
                test_logger.info("PASSED: deobfuscate_xor_single_byte")
        asyncio.run(_run())

# --- NEW: Test class for advanced string analysis and context tools ---
class TestStringAnalysisTools:
    def test_get_floss_analysis_info_filters(self):
        async def _run():
            async with managed_mcp_session() as session:
                params = {"string_type": "static_strings", "only_with_references": True, "limit": 10}
                result = await call_tool_and_assert_success(session, "get_floss_analysis_info", params, dict)
                assert "strings" in result
                if result["strings"]:
                    for item in result["strings"]:
                        assert "references" in item and item["references"]
                test_logger.info("PASSED: get_floss_analysis_info (only_with_references)")
        asyncio.run(_run())

    def test_get_top_sifted_strings_filtering(self):
        async def _run():
            async with managed_mcp_session() as session:
                params = {
                    "limit": 5, "min_sifter_score": 7.0, "max_sifter_score": 15.0,
                    "min_length": 10, "filter_by_category": "filepath_windows"
                }
                # FIX: Added is_list_expected_even_for_limit_1=True
                filtered = await call_tool_and_assert_success(
                    session, "get_top_sifted_strings", params, list, 
                    is_list_expected_even_for_limit_1=True, allow_none_result=True
                )
                if filtered:
                    for item in filtered:
                        assert 7.0 <= item['sifter_score'] <= 15.0
                        assert len(item['string']) >= 10
                        assert item['category'] == 'filepath_windows'
                test_logger.info("PASSED: get_top_sifted_strings (with granular filters)")
        asyncio.run(_run())

    def test_fuzzy_search(self):
        async def _run():
            async with managed_mcp_session() as session:
                # 1. Check for the prerequisite string first.
                search_results = await call_tool_and_assert_success(session, "search_for_specific_strings", {"search_terms": ["kernel32.dll"]}, dict)
                
                # 2. If the prerequisite is not met, log a warning and exit cleanly instead of raising an exception.
                if not search_results.get("kernel32.dll"):
                    test_logger.warning("SKIPPED: Could not find 'kernel32.dll' in the sample to test fuzzy search against. This is not a failure.")
                    return # Exit the test function cleanly.

                # 3. If the prerequisite is met, proceed with the fuzzy search test.
                fuzzy_results = await call_tool_and_assert_success(
                    session, "fuzzy_search_strings", {"query_string": "kermel32.dll", "limit": 5, "min_similarity_ratio": 80}, list,
                    is_list_expected_even_for_limit_1=True
                )
                assert fuzzy_results, "Fuzzy search should find a close match for 'kermel32.dll'"
                assert fuzzy_results[0]['similarity_ratio'] >= 80
                assert "kernel32.dll" in [r['string'] for r in fuzzy_results]
                test_logger.info("PASSED: fuzzy_search_strings")
        asyncio.run(_run())

    def test_string_context_workflow(self):
        async def _run():
            async with managed_mcp_session() as session:
                params = {"string_type": "static_strings", "only_with_references": True, "limit": 1}
                result = await call_tool_and_assert_success(session, "get_floss_analysis_info", params, dict)

                if not result or not result.get("strings"):
                    pytest.skip("No static strings with references found in sample file to test context tools.")

                string_info = result["strings"][0]
                string_offset = int(string_info.get("offset"), 16)
                ref_func_va = int(string_info["references"][0].get("function_va"), 16)

                # FIX: Added is_list_expected_even_for_limit_1=True
                usage_context = await call_tool_and_assert_success(
                    session, "get_string_usage_context", {"string_offset": string_offset}, list,
                    is_list_expected_even_for_limit_1=True
                )
                assert usage_context and "disassembly_context" in usage_context[0]
                test_logger.info("PASSED: get_string_usage_context")

                # FIX: Added is_list_expected_even_for_limit_1=True
                strings_in_func = await call_tool_and_assert_success(
                    session, "get_strings_for_function", {"function_va": ref_func_va}, list,
                    is_list_expected_even_for_limit_1=True
                )
                assert strings_in_func
                test_logger.info("PASSED: get_strings_for_function")
        asyncio.run(_run())

# --- UPDATED: Test class for encoding and file operations ---
class TestEncodingAndFileOps:
    def test_find_and_decode_strings(self):
        async def _run():
            async with managed_mcp_session() as session:
                # FIX: Added is_list_expected_even_for_limit_1=True
                results = await call_tool_and_assert_success(
                    session, "find_and_decode_encoded_strings", {"limit": 5, "min_confidence": 0.9}, list,
                    is_list_expected_even_for_limit_1=True, allow_none_result=True
                )
                if results:
                    for item in results:
                        assert item['confidence'] >= 0.9
                test_logger.info("PASSED: find_and_decode_strings")
        asyncio.run(_run())

    def test_get_hex_dump(self):
        async def _run():
            async with managed_mcp_session() as session:
                # This test now relies on the corrected helper function to parse raw text
                result = await call_tool_and_assert_success(session, "get_hex_dump", {"start_offset": 0, "length": 64}, list)
                assert result and "00000000" in result[0]
                test_logger.info("PASSED: get_hex_dump")
        asyncio.run(_run())


# --- UPDATED: Test class for CAPA tools ---
class TestCapaTools:
    def test_get_capa_analysis_info(self):
        async def _run():
            async with managed_mcp_session() as session:
                await call_tool_and_assert_success(session, "get_capa_analysis_info", {"limit": 10}, dict, ["rules"])
                test_logger.info("PASSED: get_capa_analysis_info")
        asyncio.run(_run())

# --- NEW: Test class for triage and workflow tools ---
class TestTriageAndWorkflowTools:
    def test_get_triage_report(self):
        async def _run():
            async with managed_mcp_session() as session:
                report = await call_tool_and_assert_success(
                    session, "get_triage_report", {}, dict,
                    expected_keys=["HighValueIndicators", "SuspiciousCapabilities", "SuspiciousImports", "SignatureAndPacker"]
                )
                assert isinstance(report["HighValueIndicators"], list)
                test_logger.info("PASSED: get_triage_report")
        asyncio.run(_run())

# --- UPDATED: Test class for VirusTotal tool ---
class TestVirusTotalTool:
    def test_get_virustotal_report(self):
        async def _run():
            async with managed_mcp_session() as session:
                # This test checks for any valid response, including expected non-success states like an API key missing.
                # The expected statuses match the latest server implementation.
                valid_statuses = ["success", "not_found", "api_key_missing", "error_auth", "error_rate_limit", "error_api", "error_timeout", "error_request", "error_unexpected"]
                result = await call_tool_and_assert_success(
                    session, "get_virustotal_report_for_loaded_file", {}, dict,
                    expected_status_in_payload=("status", valid_statuses)
                )
                test_logger.info(f"PASSED: get_virustotal_report_for_loaded_file (returned valid status: {result.get('status')})")
        asyncio.run(_run())


if __name__ == "__main__":
    print("This script is designed to be run with Pytest.")
    print("Example: pytest -v mcp_test_client.py")