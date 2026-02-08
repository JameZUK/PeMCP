"""MCP server setup, tool decorator, and validation helpers."""
import json
import logging

from typing import Dict, Any, Optional

from pemcp.config import (
    state, logger, FastMCP, Context,
    ANGR_AVAILABLE, MAX_MCP_RESPONSE_SIZE_BYTES, MAX_MCP_RESPONSE_SIZE_KB,
)

# --- MCP Server Setup ---
mcp_server = FastMCP("PEFileAnalyzerMCP")
tool_decorator = mcp_server.tool()

# --- MCP Feedback Helpers ---

def _check_pe_loaded(tool_name: str) -> None:
    """Raise a descriptive RuntimeError if no PE file has been loaded."""
    if state.pe_data is None or state.filepath is None:
        raise RuntimeError(
            f"[{tool_name}] No PE file is currently loaded. "
            "The server must be started with --input-file to pre-load a file for analysis. "
            "If a file was provided, startup may have failed — check the server logs."
        )

def _check_angr_ready(tool_name: str) -> None:
    """
    Raise a descriptive RuntimeError if angr is unavailable or still initializing.
    Provides actionable guidance to the MCP client.
    """
    if not ANGR_AVAILABLE:
        raise RuntimeError(
            f"[{tool_name}] The angr library is not installed on this server. "
            "Binary analysis tools (decompilation, CFG, symbolic execution, emulation) "
            "require angr. Install it with: pip install 'angr[unicorn]'"
        )
    if state.filepath is None:
        raise RuntimeError(
            f"[{tool_name}] No PE file is loaded. Cannot perform binary analysis."
        )
    # Check if background angr startup is still running
    startup_task = state.get_task("startup-angr")
    if startup_task and startup_task["status"] == "running":
        progress = startup_task.get("progress_percent", 0)
        msg = startup_task.get("progress_message", "Initializing...")
        raise RuntimeError(
            f"[{tool_name}] Angr background analysis is still in progress ({progress}%: {msg}). "
            "Please wait and retry shortly. Use check_task_status('startup-angr') to monitor progress."
        )

def _check_data_key_available(key_name: str, tool_name: str) -> None:
    """
    Check that a specific analysis data key is available in pe_data.
    Provides context-aware feedback about why data might be missing.
    """
    _check_pe_loaded(tool_name)
    if key_name not in state.pe_data:
        # Check if this was a skipped analysis
        skipped_hint = ""
        skip_map = {
            "floss_analysis": "floss", "capa_analysis": "capa",
            "yara_matches": "yara", "peid_matches": "peid"
        }
        if key_name in skip_map:
            skipped_hint = (
                f" This analysis may have been skipped via --skip-{skip_map[key_name]} at startup. "
                "Use reanalyze_loaded_pe_file to re-run the analysis."
            )
        raise RuntimeError(
            f"[{tool_name}] Analysis data for '{key_name}' is not available.{skipped_hint}"
        )

async def _check_mcp_response_size(
    ctx: Context,
    data_to_return: Any,
    tool_name: str,
    limit_param_info: Optional[str] = None
) -> Any:
    """
    Smart Size Guard: Checks if response exceeds the 64KB limit.
    If it does, it INTELLIGENTLY TRUNCATES the largest list or string in the response
    to fit within the limit, rather than raising an error.
    """
    try:
        # 1. Check initial size
        serialized_data = json.dumps(data_to_return, ensure_ascii=False)
        data_size_bytes = len(serialized_data.encode('utf-8'))

        # If it fits, return immediately
        if data_size_bytes <= MAX_MCP_RESPONSE_SIZE_BYTES:
            return data_to_return

        # 2. It's too big. Enter Truncation Mode.
        # We aim for 60KB to leave a safety buffer for the warning message
        TARGET_SIZE = MAX_MCP_RESPONSE_SIZE_BYTES - 4096

        await ctx.warning(f"Response for '{tool_name}' was {data_size_bytes/1024:.1f}KB. Auto-truncating to fit limits.")

        # Work on a copy to avoid modifying global state if it was a global obj
        # (Simple shallow copy usually sufficient for top-level modifications)
        if isinstance(data_to_return, dict):
            modified_data = data_to_return.copy()
        elif isinstance(data_to_return, list):
            modified_data = data_to_return[:]
        else:
            # Primitives (str, etc) are immutable, so we just reassign
            modified_data = data_to_return

        # 3. Heuristic: Find the largest element and chop it
        # We iterate up to 5 times to try and make it fit.
        for attempt in range(5):
            current_json = json.dumps(modified_data, ensure_ascii=False)
            current_size = len(current_json.encode('utf-8'))

            if current_size <= TARGET_SIZE:
                break # It fits now!

            reduction_ratio = TARGET_SIZE / current_size
            # Be aggressive: cut slightly more than the ratio suggests
            reduction_ratio *= 0.9

            if isinstance(modified_data, dict):
                # Find the key holding the largest amount of data
                largest_key = None
                largest_len = 0

                for k, v in modified_data.items():
                    try:
                        v_len = len(json.dumps(v, ensure_ascii=False))
                        if v_len > largest_len:
                            largest_len = v_len
                            largest_key = k
                    except Exception: continue

                if largest_key:
                    val = modified_data[largest_key]
                    if isinstance(val, list):
                        new_len = int(len(val) * reduction_ratio)
                        new_len = max(1, new_len) # Keep at least 1
                        modified_data[largest_key] = val[:new_len]
                        modified_data["_truncation_warning"] = f"Data in '{largest_key}' truncated from {len(val)} to {new_len} items to fit 64KB limit."
                    elif isinstance(val, str):
                        new_len = int(len(val) * reduction_ratio)
                        modified_data[largest_key] = val[:new_len] + "...[TRUNCATED]"
                        modified_data["_truncation_warning"] = f"String in '{largest_key}' truncated to fit limit."
                    elif isinstance(val, dict):
                        # If a dictionary is the biggest thing, simply removing items is risky structure-wise,
                        # but we can try to remove half the keys.
                        keys = list(val.keys())
                        cut_point = int(len(keys) * reduction_ratio)
                        new_dict = {k: val[k] for k in keys[:cut_point]}
                        modified_data[largest_key] = new_dict
                        modified_data["_truncation_warning"] = f"Dictionary '{largest_key}' truncated keys to fit limit."
                    else:
                        # Fallback: if we can't shrink the biggest value, we fail gracefully to avoid infinite loop
                         break

            elif isinstance(modified_data, list):
                # If the root object is a list, slice the list itself
                old_len = len(modified_data)
                new_len = int(old_len * reduction_ratio)
                modified_data = modified_data[:new_len]
                # We can't add a key to a list, so we append a warning item if possible, or rely on ctx.warning
                if len(modified_data) > 0 and isinstance(modified_data[0], dict):
                     modified_data.append({"_warning": f"List truncated from {old_len} to {new_len} items."})

            elif isinstance(modified_data, str):
                 new_len = int(len(modified_data) * reduction_ratio)
                 modified_data = modified_data[:new_len] + "...[TRUNCATED]"

        return modified_data

    except Exception as e:
        # If auto-truncation fails, fallback to the hard error so we don't crash the server
        await ctx.error(f"Auto-truncation failed: {e}")
        logger.error(f"MCP: Truncation logic failed: {e}", exc_info=True)
        # Fallback to a safe, tiny error message
        return {
            "error": "Response too large",
            "message": f"The data generated was {data_size_bytes} bytes (Limit: {MAX_MCP_RESPONSE_SIZE_BYTES}). Auto-truncation failed.",
            "suggestion": limit_param_info or "Reduce limit parameter significantly."
        }
