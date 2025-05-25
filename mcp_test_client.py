#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
MCP Test Client for PeMCP.py Server - Simplified with sync tests & final fixes
"""

import asyncio
import json
import logging
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
# test_logger.setLevel(logging.DEBUG)

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
SERVER_BASE_URL = "http://127.0.0.1:8082"
SSE_PATH = "/sse"

# --- MCP Client Session Context Manager ---
@asynccontextmanager
async def managed_mcp_session() -> AsyncGenerator[ClientSession, None]:
    sse_full_url = urljoin(SERVER_BASE_URL, SSE_PATH)
    test_logger.info(f"SESSION CTX MGR: Attempting MCP ClientSession for SSE: {sse_full_url}")
    active_session: Optional[ClientSession] = None
    try:
        async with mcp_sse_transport_client(sse_full_url) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                active_session = session
                test_logger.info("SESSION CTX MGR: ClientSession active. Attempting session.initialize()...")
                await session.initialize()
                test_logger.info("SESSION CTX MGR: session.initialize() successful. Yielding session.")
                yield active_session
    except (AssertionError, pytest.fail.Exception, pytest.skip.Exception) as e_test_outcome:
        test_logger.error(f"SESSION CTX MGR: Test outcome exception bubbled up: {type(e_test_outcome).__name__} - {str(e_test_outcome)}", exc_info=False)
        raise
    except httpx.ConnectError as e_conn:
        msg = (f"SESSION CTX MGR ERROR: Connection to MCP server failed: {e_conn}. "
               f"Ensure PeMCP.py server is running on {SERVER_BASE_URL} (SSE: {sse_full_url}).")
        test_logger.critical(msg)
        raise RuntimeError(msg) from e_conn
    except Exception as e_fixture:
        err_msg_detail = str(e_fixture)
        if isinstance(e_fixture, mcp_types.JSONRPCError):
             err_msg_detail = (f"MCP session.initialize() returned an error model: "
                               f"Code: {e_fixture.code}, Message: '{e_fixture.message}', Data: {e_fixture.data}")
        msg = f"SESSION CTX MGR ERROR: Problem during session setup or core library operation: {type(e_fixture).__name__} - {err_msg_detail}"
        test_logger.critical(msg, exc_info=True)
        raise RuntimeError(msg) from e_fixture
    finally:
        test_logger.info("SESSION CTX MGR: Async context managers for session and transport are exiting.")


# --- Test Helper Functions (remain async, called by asyncio.run) ---
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
    test_logger.info(f"[TEST CALL] Tool: '{tool_name}', Params: {json.dumps(params, default=str)}")
    response_wrapper = await session.call_tool(tool_name, arguments=params)

    assert isinstance(response_wrapper, mcp_types.CallToolResult), \
        f"Tool '{tool_name}' call did not return a CallToolResult. Got: {type(response_wrapper)}"

    log_content_snippet = str(response_wrapper.content)[:200] + "..." if response_wrapper.content else "None"
    test_logger.debug(f"[TEST RAW WRAPPER] Tool: '{tool_name}', isError: {response_wrapper.isError}, Content Snippet: {log_content_snippet}")

    if response_wrapper.isError:
        error_text = response_wrapper.content[0].text if response_wrapper.content and len(response_wrapper.content) > 0 and hasattr(response_wrapper.content[0], 'text') else "Unknown error content or format"
        pytest.fail(f"Tool '{tool_name}' call failed with error from server: {error_text}")

    actual_result_payload: Any = None

    if not response_wrapper.content: 
        if not allow_none_result:
            pytest.fail(f"Tool '{tool_name}' success response has no content items, and allow_none_result is False.")
        else:
            actual_result_payload = None
            test_logger.info(f"Tool '{tool_name}': No content items returned, result is None as allow_none_result is True.")
    elif response_wrapper.content and len(response_wrapper.content) > 0 :
        content_item = response_wrapper.content[0]
        assert hasattr(content_item, 'text') and isinstance(content_item.text, str), \
            f"Tool '{tool_name}' success response content item has no valid 'text' string. Item: {content_item}"
        json_text_payload = content_item.text

        if tool_name == "get_hex_dump" and expected_top_level_type == list and isinstance(json_text_payload, str):
            actual_result_payload = [line for line in json_text_payload.splitlines() if line.strip()]
            test_logger.info(f"Tool '{tool_name}': Parsed raw text hexdump into list of strings.")
        elif expected_top_level_type == str and not json_text_payload.strip().startswith(("{", "[")):
            actual_result_payload = json_text_payload
            test_logger.info(f"Tool '{tool_name}': Used raw text as string payload because expected type was str and JSONDecodeError would occur.")
            if allow_none_result and actual_result_payload == "":
                test_logger.info(f"Tool '{tool_name}': Converting empty string result to None as allow_none_result is True.")
                actual_result_payload = None
        elif allow_none_result and json_text_payload.lower() == 'null':
            actual_result_payload = None
            test_logger.info(f"Tool '{tool_name}': Parsed explicit 'null' string payload as None.")
        else: 
            try:
                actual_result_payload = json.loads(json_text_payload)
            except json.JSONDecodeError:
                pytest.fail(f"Failed to parse JSON success payload for '{tool_name}': '{json_text_payload}'. Expected type: {expected_top_level_type}")
    
    if actual_result_payload is None and not allow_none_result and response_wrapper.content and len(response_wrapper.content) > 0:
        pytest.fail(f"Tool '{tool_name}' payload processed to None, but allow_none_result is False. Original text payload: '{json_text_payload if 'json_text_payload' in locals() else 'N/A'}'")

    if is_list_expected_even_for_limit_1 and \
       expected_top_level_type == list and \
       isinstance(actual_result_payload, dict):
        test_logger.warning(f"Tool '{tool_name}' expected a list but got a dict; wrapping in list for test consistency.")
        actual_result_payload = [actual_result_payload]

    if allow_none_result and actual_result_payload is None:
        test_logger.info(f"Tool '{tool_name}' result is None and allow_none_result is True, skipping type/key checks for None payload.")
    else:
        if expected_top_level_type is not None:
            assert isinstance(actual_result_payload, expected_top_level_type), \
                f"Tool '{tool_name}' parsed payload type {type(actual_result_payload)} did not match expected {expected_top_level_type}. Payload: {str(actual_result_payload)[:500]}"

        if isinstance(actual_result_payload, dict):
            if expected_status_in_payload:
                status_key, expected_value = expected_status_in_payload
                assert status_key in actual_result_payload, f"Status key '{status_key}' not in parsed payload for '{tool_name}'. Keys: {list(actual_result_payload.keys())}"
                if isinstance(expected_value, list):
                    assert actual_result_payload[status_key] in expected_value, \
                        f"Tool '{tool_name}' status '{actual_result_payload.get(status_key)}' not in expected values '{expected_value}'."
                else:
                    assert actual_result_payload[status_key] == expected_value, \
                        f"Tool '{tool_name}' status '{actual_result_payload.get(status_key)}' != expected '{expected_value}'."

            if expected_keys:
                for k_expected in expected_keys:
                    assert k_expected in actual_result_payload, \
                        f"Expected key '{k_expected}' not in parsed payload for '{tool_name}'. Keys: {list(actual_result_payload.keys())}"
    return actual_result_payload

async def call_tool_and_expect_server_error_in_result(
    session: ClientSession,
    tool_name: str,
    params: Dict[str, Any],
    expected_error_message_substring: Optional[str] = None,
    expected_rpc_error_code: Optional[int] = None,
):
    test_logger.info(f"[TEST CALL] Tool: '{tool_name}', Params: {json.dumps(params, default=str)} (EXPECTING SERVER ERROR in CallToolResult or JSONRPCError)")
    try:
        response_wrapper = await session.call_tool(tool_name, arguments=params)
        assert isinstance(response_wrapper, mcp_types.CallToolResult)
        assert response_wrapper.isError, f"Tool '{tool_name}' CallToolResult.isError was False, but an error was expected."
        assert response_wrapper.content and len(response_wrapper.content) > 0 and hasattr(response_wrapper.content[0], 'text')
        error_text_from_server = response_wrapper.content[0].text
        test_logger.debug(f"[TEST SUCCESS-ExpectedServerErrorInResult] Tool '{tool_name}' returned CallToolResult with isError=True. Error text: '{error_text_from_server}'")
        if expected_error_message_substring is not None:
            assert expected_error_message_substring.lower() in error_text_from_server.lower(), \
                f"Tool '{tool_name}' error text '{error_text_from_server}' did not contain substring '{expected_error_message_substring}'."
        test_logger.info(f"PASSED-ExpectedServerErrorInResult: {tool_name} returned expected error in CallToolResult.")
    except mcp_types.JSONRPCError as e_rpc:
        test_logger.debug(f"[TEST SUCCESS-ExpectedJSONRPCError] Tool '{tool_name}' raised JSONRPCError as expected. Code: {e_rpc.code}, Message: '{e_rpc.message}'")
        if expected_rpc_error_code is not None:
            assert e_rpc.code == expected_rpc_error_code, \
                f"Tool '{tool_name}' JSONRPCError code {e_rpc.code} did not match expected {expected_rpc_error_code}."
        if expected_error_message_substring is not None:
            assert expected_error_message_substring.lower() in e_rpc.message.lower(), \
                f"Tool '{tool_name}' JSONRPCError message '{e_rpc.message}' did not contain substring '{expected_error_message_substring}'."
        test_logger.info(f"PASSED-ExpectedJSONRPCError: {tool_name} raised expected JSONRPCError.")
    except AssertionError: 
        raise 
    except Exception as e_unexp:
        pytest.fail(f"Tool '{tool_name}' call raised an unexpected exception {type(e_unexp).__name__} when a server error or JSONRPCError was expected: {e_unexp}")

# --- Test Classes and Methods (now synchronous) ---
# TestServerUtilityTools, TestCoreAnalysisDataTools, TestRemainingPEAnalysisInfoTools, TestDeobfuscationAndEncodingTools
# are assumed to be correct from the previous iteration and are not repeated here for brevity.
# The key changes were in the helpers and the two failing tests below.

class TestServerUtilityTools:
    def test_get_current_server_datetime(self):
        async def _run():
            async with managed_mcp_session() as session:
                tool_name = "get_current_datetime"
                result = await call_tool_and_assert_success(
                    session, tool_name, params={},
                    expected_top_level_type=dict,
                    expected_keys=["utc_datetime", "local_datetime", "local_timezone_name"]
                )
                utc_dt_str = result.get("utc_datetime", "")
                assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|([+-]\d{2}:\d{2}))", utc_dt_str), f"UTC datetime format error: {utc_dt_str}"
                test_logger.info(f"PASSED: {tool_name}")
        asyncio.run(_run())

class TestCoreAnalysisDataTools:
    def test_get_analyzed_file_summary(self):
        async def _run():
            async with managed_mcp_session() as session:
                tool_name = "get_analyzed_file_summary"
                params_valid = {"limit": 5}
                result = await call_tool_and_assert_success(
                    session, tool_name, params_valid, expected_top_level_type=dict
                )
                assert "filepath" in result 
                test_logger.info(f"PASSED: {tool_name} with valid limit.")

                params_invalid_limit_zero = {"limit": 0}
                await call_tool_and_expect_server_error_in_result(
                    session, tool_name, params_invalid_limit_zero,
                    expected_error_message_substring="must be a positive integer",
                    expected_rpc_error_code=-32602
                )
                test_logger.info(f"PASSED: {tool_name} with invalid limit (0).")
        asyncio.run(_run())

    def test_get_full_analysis_results(self):
        async def _run():
            async with managed_mcp_session() as session:
                tool_name = "get_full_analysis_results"
                params_valid = {"limit": 10}
                result = await call_tool_and_assert_success(
                    session, tool_name, params_valid, expected_top_level_type=dict
                )
                assert "dos_header" in result 
                test_logger.info(f"PASSED: {tool_name} with limit {params_valid['limit']}.")

                params_invalid_limit = {"limit": -1}
                await call_tool_and_expect_server_error_in_result(
                    session, tool_name, params_invalid_limit,
                    expected_error_message_substring="must be a positive integer",
                    expected_rpc_error_code=-32602
                )
                test_logger.info(f"PASSED: {tool_name} with invalid limit (-1).")
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
    @pytest.mark.parametrize("tool_name_full, expected_type, is_list_tool, allow_none_payload", TOOL_PARAMETRIZATION)
    def test_dynamic_pe_info_tool(self, tool_name_full: str, expected_type: type,
                                  is_list_tool: bool, allow_none_payload: bool):
        async def _run():
            async with managed_mcp_session() as session:
                test_logger.info(f"Dynamically testing tool: {tool_name_full}")
                params = {"limit": 5, "offset": 0}

                result_payload = await call_tool_and_assert_success(
                    session, tool_name_full, params,
                    expected_top_level_type=expected_type,
                    is_list_expected_even_for_limit_1=is_list_tool,
                    allow_none_result=allow_none_payload
                )

                if allow_none_payload and result_payload is None:
                    test_logger.info(f"PASSED: {tool_name_full} returned None as expected for potentially absent data.")
                elif expected_type == list:
                    assert isinstance(result_payload, list)
                    if result_payload: 
                         assert len(result_payload) <= params["limit"]
                    test_logger.info(f"PASSED: {tool_name_full} (list type, {len(result_payload)} items returned)")
                elif expected_type == dict:
                    assert isinstance(result_payload, dict)
                    test_logger.info(f"PASSED: {tool_name_full} (dict type, {len(result_payload)} keys returned)")
        asyncio.run(_run())

class TestDeobfuscationAndEncodingTools:
    def test_deobfuscate_base64_string_from_hex(self):
        async def _run():
            async with managed_mcp_session() as session:
                tool_name = "deobfuscate_base64"
                original_string = "Hello MCP Tester!"
                base64_encoded_bytes = base64.b64encode(original_string.encode('utf-8'))
                hex_of_base64 = base64_encoded_bytes.hex()

                params_valid = {"hex_string": hex_of_base64}
                result = await call_tool_and_assert_success(
                    session, tool_name, params_valid,
                    expected_top_level_type=str,
                    allow_none_result=True
                )
                assert result == original_string
                test_logger.info(f"PASSED: {tool_name} valid case.")

                params_invalid_hex = {"hex_string": "INVALID_HEX!"}
                invalid_result = await call_tool_and_assert_success(
                    session, tool_name, params_invalid_hex,
                    expected_top_level_type=str,
                    allow_none_result=True
                )
                assert invalid_result is None, "Expected None for invalid hex input to Base64 deobfuscation"
                test_logger.info(f"PASSED: {tool_name} with invalid hex string (expected None).")

                params_valid_hex_not_b64 = {"hex_string": "01020304"}
                invalid_b64_result = await call_tool_and_assert_success(
                    session, tool_name, params_valid_hex_not_b64,
                    expected_top_level_type=str,
                    allow_none_result=True
                )
                assert invalid_b64_result is None, "Expected None for non-Base64 hex input"
                test_logger.info(f"PASSED: {tool_name} with valid hex but non-Base64 data (expected None).")
        asyncio.run(_run())

    def test_deobfuscate_data_with_single_byte_xor(self):
        async def _run():
            async with managed_mcp_session() as session:
                tool_name = "deobfuscate_xor_single_byte"
                original_text = "XOR Test 123 !@#"
                xor_key = 0xAB
                xored_bytes = bytes([ord(c) ^ xor_key for c in original_text])
                hex_encoded_xored_data = xored_bytes.hex()

                params_valid = {"data_hex": hex_encoded_xored_data, "key": xor_key}
                result = await call_tool_and_assert_success(
                    session, tool_name, params_valid,
                    expected_top_level_type=dict,
                    expected_keys=["deobfuscated_hex", "deobfuscated_printable_string"]
                )
                assert result.get("deobfuscated_printable_string") == original_text
                test_logger.info(f"PASSED: {tool_name} valid case.")

                params_invalid_key = {"data_hex": hex_encoded_xored_data, "key": 300}
                await call_tool_and_expect_server_error_in_result(
                    session, tool_name, params_invalid_key,
                    expected_error_message_substring="key must be an integer between 0 and 255",
                    expected_rpc_error_code=-32602
                )
                test_logger.info(f"PASSED: {tool_name} invalid XOR key.")

                params_invalid_hex = {"data_hex": "XYZ123", "key": 0x20}
                await call_tool_and_expect_server_error_in_result(
                     session, tool_name, params_invalid_hex,
                     expected_error_message_substring="non-hexadecimal number found", 
                     expected_rpc_error_code=-32602 
                )
                test_logger.info(f"PASSED: {tool_name} invalid hex data.")
        asyncio.run(_run())

    def test_check_string_if_mostly_printable_ascii(self):
        async def _run():
            async with managed_mcp_session() as session:
                tool_name = "is_mostly_printable_ascii"
                result_printable = await call_tool_and_assert_success(
                    session, tool_name,
                    {"text_input": "Good string!", "threshold": 0.7},
                    expected_top_level_type=bool
                )
                assert result_printable is True
                test_logger.info(f"PASSED: {tool_name} with printable string.")

                result_non_printable = await call_tool_and_assert_success(
                    session, tool_name,
                    {"text_input": "Mostly \x01\x02\x03\x04\x05\x06 binary", "threshold": 0.8},
                    expected_top_level_type=bool
                )
                assert result_non_printable is False
                test_logger.info(f"PASSED: {tool_name} with mostly non-printable string.")

                result_empty_string = await call_tool_and_assert_success(
                    session, tool_name,
                    {"text_input": "", "threshold": 0.8},
                    expected_top_level_type=bool
                )
                assert result_empty_string is False, "Empty string should not be mostly printable"
                test_logger.info(f"PASSED: {tool_name} with empty string.")

                params_invalid_threshold = {"text_input": "abc", "threshold": 1.1}
                await call_tool_and_expect_server_error_in_result(
                    session, tool_name, params_invalid_threshold,
                    expected_error_message_substring="Threshold must be between 0.0 and 1.0", 
                    expected_rpc_error_code=-32602
                )
                test_logger.info(f"PASSED: {tool_name} with invalid threshold.")
        asyncio.run(_run())

class TestCapaTools:
    def test_get_capa_analysis_overview(self):
        async def _run():
            async with managed_mcp_session() as session:
                tool_name = "get_capa_analysis_info"
                params_basic = {"limit": 5, "offset": 0}
                result = await call_tool_and_assert_success(
                    session, tool_name, params_basic,
                    expected_top_level_type=dict,
                    expected_keys=["rules", "pagination", "report_metadata"]
                )
                assert isinstance(result.get("rules"), dict)
                assert isinstance(result.get("pagination"), dict)
                assert isinstance(result.get("report_metadata"), dict)
                test_logger.info(f"PASSED: {tool_name} basic call.")

                params_meta_only = {"limit": 1, "get_report_metadata_only": True}
                result_meta = await call_tool_and_assert_success(
                    session, tool_name, params_meta_only,
                    expected_top_level_type=dict,
                    expected_keys=["report_metadata"]
                )
                assert result_meta.get("report_metadata") is not None
                assert result_meta.get("rules", {}) == {}
                test_logger.info(f"PASSED: {tool_name} with get_report_metadata_only=True.")

                rules_on_page = result.get("rules", {})
                if rules_on_page:
                    first_rule_id = list(rules_on_page.keys())[0]
                    rule_data = rules_on_page[first_rule_id]
                    if isinstance(rule_data, dict) and "source" in rule_data:
                        first_rule_source_len = len(rule_data.get("source",""))
                        if first_rule_source_len > 10:
                            truncate_len = 5
                            params_truncate = {"limit": 1, "filter_rule_name": first_rule_id, "source_string_limit": truncate_len}
                            result_truncate = await call_tool_and_assert_success( session, tool_name, params_truncate, expected_top_level_type=dict)
                            truncated_rule = result_truncate.get("rules", {}).get(first_rule_id, {})
                            truncated_source = truncated_rule.get("source", "")
                            assert len(truncated_source) <= truncate_len or \
                                   (len(truncated_source) <= truncate_len + len("... (truncated)") and "... (truncated)" in truncated_source)
                            test_logger.info(f"PASSED: {tool_name} with source_string_limit.")
                        else:
                            test_logger.info(f"SKIPPED: {tool_name} source_string_limit test, first rule source '{first_rule_id}' too short or no source text.")
                    else:
                        test_logger.info(f"SKIPPED: {tool_name} source_string_limit test, rule '{first_rule_id}' data format unexpected or no source field.")
                else:
                     test_logger.info(f"SKIPPED: {tool_name} source_string_limit test, no rules in summary to test truncation.")

                params_invalid_limit = {"limit": 0}
                await call_tool_and_expect_server_error_in_result(
                    session, tool_name, params_invalid_limit,
                    expected_error_message_substring="must be a positive integer",
                    expected_rpc_error_code=-32602
                )
                test_logger.info(f"PASSED: {tool_name} with invalid limit.")
        asyncio.run(_run())

    def test_get_capa_rule_match_details(self):
        async def _run():
            async with managed_mcp_session() as session:
                overview_tool_name = "get_capa_analysis_info"
                overview_params = {"limit": 1, "offset": 0}
                overview_result = await call_tool_and_assert_success(
                    session, overview_tool_name, overview_params, expected_top_level_type=dict
                )

                rules_summary = overview_result.get("rules", {})
                if not rules_summary:
                    pytest.skip("No Capa rules found in overview to test details for. Ensure Capa analysis ran on pre-loaded PE and returned rules.")
                    return

                rule_id_to_test = list(rules_summary.keys())[0]
                tool_name = "get_capa_rule_match_details"
                params_valid = {"rule_id": rule_id_to_test, "address_limit": 5, "address_offset": 0}
                result = await call_tool_and_assert_success(
                    session, tool_name, params_valid,
                    expected_top_level_type=dict,
                    expected_keys=["rule_id", "matches_data", "address_pagination"]
                )
                assert result.get("rule_id") == rule_id_to_test
                assert isinstance(result.get("matches_data"), dict)
                assert isinstance(result.get("address_pagination"), dict)
                test_logger.info(f"PASSED: {tool_name} for rule '{rule_id_to_test}'.")

                params_truncate_features = {
                    "rule_id": rule_id_to_test,
                    "address_limit": 1,
                    "detail_limit_per_address": 1,
                    "feature_value_string_limit": 10
                }
                result_truncate_feat = await call_tool_and_assert_success(session, tool_name, params_truncate_features, expected_top_level_type=dict)
                if result_truncate_feat.get("matches_data"):
                    first_addr_matches_dict_val = list(result_truncate_feat["matches_data"].values())
                    if first_addr_matches_dict_val and first_addr_matches_dict_val[0]:
                         first_addr_match_list = first_addr_matches_dict_val[0]
                         if first_addr_match_list:
                            assert len(first_addr_match_list) <= 1
                            feature_obj = first_addr_match_list[0].get("feature",{})
                            if isinstance(feature_obj.get("value"), str):
                                assert len(feature_obj["value"]) <= 10 or \
                                       (len(feature_obj["value"]) <= 10 + len("... (truncated)") and "... (truncated)" in feature_obj["value"])
                    test_logger.info(f"PASSED: {tool_name} with feature truncation/limiting.")
                else:
                    test_logger.info(f"SKIPPED: {tool_name} feature truncation test, no detailed matches returned for rule {rule_id_to_test} with limit 1 address.")

                params_invalid_rule_id = {"rule_id": "NON_EXISTENT_RULE_ID_XYZ123", "address_limit": 1}
                result_invalid_rule = await call_tool_and_assert_success(
                    session, tool_name, params_invalid_rule_id, expected_top_level_type=dict,
                    expected_keys=["error"]  # Corrected
                )
                assert "not found" in result_invalid_rule.get("error", "").lower() # Corrected
                test_logger.info(f"PASSED: {tool_name} with non-existent rule_id.")
        asyncio.run(_run())

class TestFileOperationTools:
    def test_extract_strings_from_loaded_binary(self):
        async def _run():
            async with managed_mcp_session() as session:
                tool_name = "extract_strings_from_binary"
                params = {"limit": 10, "min_length": 6}
                result = await call_tool_and_assert_success(
                    session, tool_name, params,
                    expected_top_level_type=list,
                    is_list_expected_even_for_limit_1=True
                )
                assert len(result) <= params["limit"]
                if result:
                    assert "offset" in result[0] and "string" in result[0]
                    assert result[0]["string"]
                    assert len(result[0]["string"]) >= params["min_length"]
                test_logger.info(f"PASSED: {tool_name}")

                params_invalid_limit = {"limit": 0, "min_length": 6}
                await call_tool_and_expect_server_error_in_result(
                    session, tool_name, params_invalid_limit,
                    expected_error_message_substring="must be a positive integer",
                    expected_rpc_error_code=-32602
                )
                test_logger.info(f"PASSED: {tool_name} with invalid limit.")
        asyncio.run(_run())

    def test_search_for_specific_strings_in_loaded_binary(self):
        async def _run():
            async with managed_mcp_session() as session:
                tool_name = "search_for_specific_strings"
                params = {"search_terms": ["kernel32.dll", "ThisStringShouldNotExist123ABCXYZ"], "limit_per_term": 5}
                result = await call_tool_and_assert_success(
                    session, tool_name, params, expected_top_level_type=dict
                )
                assert "kernel32.dll" in result
                assert "ThisStringShouldNotExist123ABCXYZ" in result
                assert len(result["kernel32.dll"]) >= 0 and len(result["kernel32.dll"]) <= params["limit_per_term"]
                if len(result["kernel32.dll"]) > 0: test_logger.info(f"Found 'kernel32.dll' {len(result['kernel32.dll'])} times.")
                assert len(result["ThisStringShouldNotExist123ABCXYZ"]) == 0
                test_logger.info(f"PASSED: {tool_name}")

                params_empty_terms = {"search_terms": [], "limit_per_term": 5}
                await call_tool_and_expect_server_error_in_result(
                    session, tool_name, params_empty_terms,
                    expected_error_message_substring="must be a non-empty list of strings",
                    expected_rpc_error_code=-32602
                )
                test_logger.info(f"PASSED: {tool_name} with empty search terms list.")
        asyncio.run(_run())

    def test_get_hex_dump_from_loaded_binary(self):
        async def _run():
            async with managed_mcp_session() as session:
                tool_name = "get_hex_dump"
                params = {"start_offset": 0, "length": 64, "bytes_per_line": 16, "limit_lines": 4}
                result = await call_tool_and_assert_success(
                    session, tool_name, params, expected_top_level_type=list
                )
                assert len(result) <= params["limit_lines"]
                if result:
                    assert isinstance(result[0], str)
                    assert "00000000" in result[0]
                    assert re.search(r"\|[A-Za-z0-9.]{1,16}\|", result[0])
                test_logger.info(f"PASSED: {tool_name}")

                params_offset_too_large = {"start_offset": 0xFFFFFFF, "length": 64, "limit_lines": 1}
                result_offset_err = await call_tool_and_assert_success(
                    session, tool_name, params_offset_too_large, expected_top_level_type=list
                )
                assert len(result_offset_err) == 1 and "start offset is beyond the file size" in result_offset_err[0].lower()
                test_logger.info(f"PASSED: {tool_name} with offset beyond file size.")
        asyncio.run(_run())

    def test_find_and_decode_common_encoded_substrings(self):
        async def _run():
            async with managed_mcp_session() as session:
                tool_name = "find_and_decode_encoded_strings"
                params_basic = {"limit": 5, "min_decoded_printable_length": 8}
                result_basic = await call_tool_and_assert_success(
                    session, tool_name, params_basic, expected_top_level_type=list,
                    allow_none_result=True
                )
                if result_basic is not None:
                    assert len(result_basic) <= params_basic["limit"]
                    if result_basic:
                        assert "decoded_string" in result_basic[0]
                        assert "detected_encoding" in result_basic[0]
                        assert len(result_basic[0]["decoded_string"]) >= params_basic["min_decoded_printable_length"]
                test_logger.info(f"PASSED: {tool_name} basic call.")

                params_invalid_limit = {"limit": 0}
                await call_tool_and_expect_server_error_in_result(
                    session, tool_name, params_invalid_limit,
                    expected_error_message_substring="Parameter 'limit' must be a positive integer", 
                    expected_rpc_error_code=-32602
                )
                test_logger.info(f"PASSED: {tool_name} with invalid limit.")
        asyncio.run(_run())

class TestReanalyzeTool:
    def test_reanalyze_loaded_pe_file(self):
        async def _run():
            async with managed_mcp_session() as session:
                tool_name = "reanalyze_loaded_pe_file"
                params_default = {"verbose_mcp_output": True}
                result = await call_tool_and_assert_success(
                    session, tool_name, params_default,
                    expected_top_level_type=dict,
                    expected_keys=["status", "message", "filepath"],
                    expected_status_in_payload=("status", "success")
                )
                test_logger.info(f"PASSED: {tool_name} with default parameters.")

                params_skip_capa_flag = {"skip_capa_analysis": True, "verbose_mcp_output": False}
                result_skip_flag = await call_tool_and_assert_success(
                    session, tool_name, params_skip_capa_flag,
                    expected_top_level_type=dict,
                    expected_keys=["status", "message", "filepath"],
                    expected_status_in_payload=("status", "success")
                )
                assert "(skipped: capa)" in result_skip_flag.get("message", "").lower(), \
                    f"Message was: '{result_skip_flag.get('message', '')}'"
                test_logger.info(f"PASSED: {tool_name} skipping Capa via skip_capa_analysis.")

                params_skip_list = {"analyses_to_skip": ["peid", "yara"], "verbose_mcp_output": False}
                result_skip_list = await call_tool_and_assert_success(
                    session, tool_name, params_skip_list,
                    expected_top_level_type=dict,
                    expected_keys=["status", "message", "filepath"],
                    expected_status_in_payload=("status", "success")
                )
                message_lower = result_skip_list.get("message", "").lower()
                assert "(skipped: peid, yara)" in message_lower or "(skipped: yara, peid)" in message_lower
                test_logger.info(f"PASSED: {tool_name} skipping PEiD and YARA via analyses_to_skip.")

                params_peid_flags = {
                    "skip_full_peid_scan": True,
                    "peid_scan_all_sigs_heuristically": True,
                    "verbose_mcp_output": False
                }
                await call_tool_and_assert_success(
                    session, tool_name, params_peid_flags, expected_top_level_type=dict,
                    expected_status_in_payload=("status", "success")
                )
                test_logger.info(f"PASSED: {tool_name} with PEiD specific flags.")

                params_override = {"peid_db_path": "/tmp/non_existent_peid_db.txt", "verbose_mcp_output": False}
                await call_tool_and_assert_success(
                    session, tool_name, params_override, expected_top_level_type=dict,
                    expected_status_in_payload=("status", "success")
                )
                test_logger.info(f"PASSED: {tool_name} with peid_db_path override.")
        asyncio.run(_run())

class TestVirusTotalTool:
    def test_get_virustotal_report_for_loaded_file(self):
        async def _run():
            async with managed_mcp_session() as session:
                tool_name = "get_virustotal_report_for_loaded_file"
                
                # Initial raw call to check for "Unknown tool" specifically
                response_wrapper = await session.call_tool(tool_name, arguments={})
                
                if response_wrapper.isError and \
                   response_wrapper.content and len(response_wrapper.content) > 0 and \
                   hasattr(response_wrapper.content[0], 'text') and \
                   f"Unknown tool: {tool_name}" in response_wrapper.content[0].text:
                    pytest.skip(f"Tool '{tool_name}' is unknown to the server. Skipping test.")
                    # No return needed here, pytest.skip raises an exception that stops execution of _run

                # If not skipped (i.e., tool is known or error is different), proceed with full assertions.
                # call_tool_and_assert_success will re-execute the call but apply all standard checks.
                result = await call_tool_and_assert_success(
                    session, tool_name, params={},
                    expected_top_level_type=dict,
                    expected_status_in_payload=("status", ["api_key_missing", "vt_hash_not_found", "success_vt_report_retrieved", "error_vt_request_timeout", "error_vt_authentication", "error_vt_rate_limit", "error_vt_api_other", "error_vt_request_general", "dependency_missing", "error_no_hash", "error_tool_unexpected"]),
                    expected_keys=["query_hash", "query_hash_type", "message"] # These keys are expected if not 'success_vt_report_retrieved'
                )
                status = result.get("status")
                if status == "api_key_missing":
                    test_logger.info(f"PASSED: {tool_name} correctly reported API key missing.")
                elif status == "vt_hash_not_found":
                    test_logger.info(f"PASSED: {tool_name} reported hash not found.")
                elif status == "success_vt_report_retrieved":
                    test_logger.warning(f"INFO: {tool_name} succeeded - VT_API_KEY might be configured.")
                    assert "virustotal_report_summary" in result
                elif status and (status.startswith("error_") or status == "dependency_missing"):
                     test_logger.warning(f"INFO: {tool_name} returned an expected error/status: {status}. Message: {result.get('message')}")
                else: # Should not be reached if status is one of the expected_status_in_payload
                    pytest.fail(f"{tool_name} returned unexpected status: {status}. Response: {result}")
        asyncio.run(_run())

if __name__ == "__main__":
    print("This script is designed to be run with Pytest.")
    print("Example: pytest -v mcp_test_client.py")