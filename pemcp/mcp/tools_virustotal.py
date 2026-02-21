"""MCP tools for VirusTotal API integration."""
import datetime
import asyncio
from typing import Dict, Any, Optional
from pemcp.config import state, logger, Context, REQUESTS_AVAILABLE, VT_API_URL_FILE_REPORT
from pemcp.user_config import get_config_value
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size
if REQUESTS_AVAILABLE:
    import requests


def _safe_timestamp(ts):
    if ts is None:
        return None
    try:
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()
    except (OSError, ValueError, TypeError):
        return None


@tool_decorator
async def get_virustotal_report_for_loaded_file(ctx: Context) -> Dict[str, Any]:
    """
    Retrieves a summary report from VirusTotal for the pre-loaded PE file using its hash.
    Requires the 'requests' library and a VirusTotal API key set in the VT_API_KEY environment variable.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary containing VirusTotal report summary or an error status.
        Includes hashes (MD5, SHA1, SHA256, ssdeep) reported by VirusTotal,
        detection statistics, and other relevant metadata.

    Raises:
        RuntimeError: If no PE file is loaded or hashes are unavailable.
        ValueError: If the response size exceeds the server limit.
    """

    tool_name = "get_virustotal_report_for_loaded_file"
    await ctx.info(f"Request for VirusTotal report for the loaded file.")

    if not state.pe_data or 'file_hashes' not in state.pe_data:
        raise RuntimeError("No PE file loaded or file hashes are unavailable. Cannot query VirusTotal.")

    file_hashes = state.pe_data['file_hashes']
    main_hash_value: Optional[str] = None
    hash_type_used: Optional[str] = None

    if file_hashes.get('sha256'):
        main_hash_value = file_hashes['sha256']
        hash_type_used = "sha256"
    elif file_hashes.get('sha1'):
        main_hash_value = file_hashes['sha1']
        hash_type_used = "sha1"
    elif file_hashes.get('md5'):
        main_hash_value = file_hashes['md5']
        hash_type_used = "md5"

    if not main_hash_value or not hash_type_used:
        await ctx.error("No suitable hash (SHA256, SHA1, MD5) available for VirusTotal query.")
        return await _check_mcp_response_size(ctx, {
            "status": "error",
            "message": "No suitable file hash (SHA256, SHA1, MD5) available for VirusTotal query.",
            "query_hash_type": None,
            "query_hash": None
        }, tool_name)


    # Read API key at runtime (supports set_api_key and env var changes)
    vt_api_key = get_config_value("vt_api_key")

    if not vt_api_key:
        await ctx.warning("VirusTotal API key is not configured. Set it with set_api_key('vt_api_key', '<your-key>') or the VT_API_KEY environment variable.")
        return await _check_mcp_response_size(ctx, {
            "status": "api_key_missing",
            "message": "VirusTotal API key is not configured. Use the set_api_key tool or set the VT_API_KEY environment variable.",
            "query_hash_type": hash_type_used,
            "query_hash": main_hash_value
        }, tool_name)

    if not REQUESTS_AVAILABLE:
        await ctx.warning("'requests' library is not available. Skipping VirusTotal lookup.")
        return await _check_mcp_response_size(ctx, {
            "status": "requests_unavailable",
            "message": "'requests' library is not installed/available, which is required for VirusTotal queries.",
            "query_hash_type": hash_type_used,
            "query_hash": main_hash_value
        }, tool_name)

    headers = {"x-apikey": vt_api_key}
    api_url = f"{VT_API_URL_FILE_REPORT}{main_hash_value}"
    response_payload: Dict[str, Any] = {
        "status": "pending",
        "query_hash_type": hash_type_used,
        "query_hash": main_hash_value,
        "locally_calculated_ssdeep": file_hashes.get('ssdeep'),
    }

    try:
        await ctx.info(f"Querying VirusTotal API for hash: {main_hash_value}")
        http_response = await asyncio.to_thread(requests.get, api_url, headers=headers, timeout=20)

        if http_response.status_code == 200:
            vt_json_response = http_response.json()
            vt_attributes = vt_json_response.get("data", {}).get("attributes", {})

            vt_data_summary = {
                "report_link": f"https://www.virustotal.com/gui/file/{main_hash_value}",
                "retrieved_hashes": {
                    "md5": vt_attributes.get("md5"),
                    "sha1": vt_attributes.get("sha1"),
                    "sha256": vt_attributes.get("sha256"),
                    "ssdeep_from_vt": vt_attributes.get("ssdeep"),
                },
                "detection_stats": vt_attributes.get("last_analysis_stats"),
                "last_analysis_date_utc": _safe_timestamp(vt_attributes.get("last_analysis_date")),
                "first_submission_date_utc": _safe_timestamp(vt_attributes.get("first_submission_date")),
                "last_submission_date_utc": _safe_timestamp(vt_attributes.get("last_submission_date")),
                "reputation": vt_attributes.get("reputation"),
                "tags": vt_attributes.get("tags", []),
                "suggested_threat_label": vt_attributes.get("popular_threat_classification", {}).get("suggested_threat_label"),
                "trid": vt_attributes.get("trid", []),
                "meaningful_name": vt_attributes.get("meaningful_name"),
                "names": list(set(vt_attributes.get("names", [])))[:10],
                "size": vt_attributes.get("size"),
            }
            response_payload["status"] = "success"
            response_payload["message"] = "VirusTotal report summary retrieved successfully."
            response_payload["virustotal_report_summary"] = vt_data_summary
            await ctx.info(f"Successfully retrieved VirusTotal report for {main_hash_value}")

        elif http_response.status_code == 404:
            response_payload["status"] = "not_found"
            response_payload["message"] = f"Hash {main_hash_value} not found on VirusTotal."
            await ctx.info(f"Hash {main_hash_value} not found on VirusTotal.")
        elif http_response.status_code == 401:
            response_payload["status"] = "error_auth"
            response_payload["message"] = "VirusTotal API authentication failed. Check your VT_API_KEY."
            await ctx.error("VirusTotal API authentication failed (401).")
        elif http_response.status_code == 429:
            response_payload["status"] = "error_rate_limit"
            response_payload["message"] = "VirusTotal API rate limit exceeded. Please try again later."
            await ctx.warning("VirusTotal API rate limit exceeded (429).")
        else:
            response_payload["status"] = "error_api"
            response_payload["message"] = f"VirusTotal API returned an error. Status Code: {http_response.status_code}. Response: {http_response.text[:200]}"
            await ctx.error(f"VirusTotal API error for {main_hash_value}: {http_response.status_code} - {http_response.text[:200]}")

    except requests.exceptions.Timeout:
        response_payload["status"] = "error_timeout"
        response_payload["message"] = "Request to VirusTotal API timed out."
        await ctx.error(f"VirusTotal API request timed out for hash {main_hash_value}.")
    except requests.exceptions.RequestException as e_req:
        response_payload["status"] = "error_request"
        response_payload["message"] = f"Error during VirusTotal API request: {e_req!s}"
        await ctx.error(f"VirusTotal API request error for {main_hash_value}: {e_req}")
    except Exception as e:
        response_payload["status"] = "error_unexpected"
        response_payload["message"] = f"An unexpected error occurred while fetching VirusTotal data: {e!s}"
        logger.error("MCP: Unexpected error in %s for %s: %s", tool_name, main_hash_value, e, exc_info=True)
        await ctx.error(f"Unexpected error in {tool_name}: {e}")

    limit_info_str = "parameters for this tool (none currently, rely on server-side summarization)"
    return await _check_mcp_response_size(ctx, response_payload, tool_name, limit_info_str)
