"""MCP tools for importing and analysing code coverage data.

Supports DynamoRIO drcov binary format, Frida/Lighthouse JSON, and generic
CSV coverage files.  Coverage is overlaid onto the loaded binary's function
map to identify executed vs. uncovered code regions.
"""
import asyncio
import json
import os
import struct
from typing import Any, Dict, List, Optional

from arkana.config import state, logger, Context
from arkana.constants import MAX_TOOL_LIMIT
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size

# Safety caps
_MAX_COVERAGE_ENTRIES = 500_000
_MAX_COVERAGE_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
_MAX_MODULES = 1_000


# ---------------------------------------------------------------------------
# drcov binary format parser
# ---------------------------------------------------------------------------

def _parse_drcov(data: bytes) -> Dict[str, Any]:
    """Parse DynamoRIO drcov binary format.

    Format:
        Header lines (ASCII):
            DRCOV VERSION: 2
            DRCOV FLAVOR: drcov
            Module Table: version 2, count <N>
            Columns: id, base, end, entry, ...path
            <N module lines>
            BB Table: <M> bbs
        Binary basic block entries (each 8 bytes):
            uint32 start (offset from module base)
            uint16 size
            uint16 mod_id
    """
    # Find header boundary — everything before "BB Table:" is ASCII
    bb_marker = b"BB Table:"
    bb_idx = data.find(bb_marker)
    if bb_idx < 0:
        raise ValueError("Not a valid drcov file: missing 'BB Table:' marker")

    header_text = data[:bb_idx + 200].decode("ascii", errors="replace")

    # Parse module table
    modules = []
    mod_table_start = header_text.find("Module Table:")
    if mod_table_start < 0:
        raise ValueError("Not a valid drcov file: missing 'Module Table:'")

    # Find "Columns:" line (skip it), then read module lines
    lines = header_text[mod_table_start:].split("\n")
    for line in lines:
        if line.startswith("Module Table:"):
            # Extract count
            parts = line.split("count")
            if len(parts) >= 2:
                try:
                    int(parts[1].strip().rstrip(","))  # Validate count is numeric
                except ValueError:
                    pass
        elif line.startswith("Columns:"):
            continue
        elif line.strip() and not line.startswith("BB Table:"):
            # Module line: id, base, end, entry, checksum, timestamp, path
            parts = line.strip().split(",", 6)
            if len(parts) >= 3:
                try:
                    mod_id = int(parts[0].strip())
                    mod_base = int(parts[1].strip(), 16) if parts[1].strip().startswith("0x") else int(parts[1].strip())
                    mod_end = int(parts[2].strip(), 16) if parts[2].strip().startswith("0x") else int(parts[2].strip())
                    mod_path = parts[-1].strip() if len(parts) > 3 else ""
                    modules.append({
                        "id": mod_id,
                        "base": mod_base,
                        "end": mod_end,
                        "path": mod_path,
                        "name": os.path.basename(mod_path) if mod_path else f"module_{mod_id}",
                    })
                except (ValueError, OverflowError):
                    continue
            if len(modules) >= _MAX_MODULES:
                break

    # Find start of binary BB data
    bb_line_end = data.find(b"\n", bb_idx)
    if bb_line_end < 0:
        raise ValueError("Malformed drcov: no newline after BB Table header")

    # Parse BB count from header
    bb_header = data[bb_idx:bb_line_end].decode("ascii", errors="replace")
    bb_count = 0
    for part in bb_header.split():
        try:
            bb_count = int(part)
        except ValueError:
            continue

    bb_data_start = bb_line_end + 1
    bb_entry_size = 8  # uint32 start + uint16 size + uint16 mod_id

    # Parse basic block entries
    blocks = []
    offset = bb_data_start
    count = 0
    while offset + bb_entry_size <= len(data) and count < min(bb_count, _MAX_COVERAGE_ENTRIES):
        start_off, size, mod_id = struct.unpack_from("<IHH", data, offset)
        offset += bb_entry_size
        count += 1

        # Resolve absolute address using module base
        abs_addr = start_off
        if 0 <= mod_id < len(modules):
            abs_addr = modules[mod_id]["base"] + start_off

        blocks.append({
            "address": abs_addr,
            "size": size,
            "module_id": mod_id,
        })

    return {
        "format": "drcov",
        "modules": modules,
        "blocks": blocks,
        "block_count": len(blocks),
        "module_count": len(modules),
    }


# ---------------------------------------------------------------------------
# Lighthouse / Frida JSON coverage parser
# ---------------------------------------------------------------------------

def _parse_json_coverage(data: bytes) -> Dict[str, Any]:
    """Parse JSON coverage (Lighthouse/Frida format).

    Expected formats:
        {"coverage": [{"address": 0x..., "size": N}, ...]}
        {"modules": [...], "blocks": [...]}
        [{"start": 0x..., "end": 0x...}, ...]  (list of ranges)
    """
    try:
        obj = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"Invalid JSON coverage file: {e}")

    blocks = []

    if isinstance(obj, dict):
        # Format: {"coverage": [...]} or {"blocks": [...]}
        raw_blocks = obj.get("coverage") or obj.get("blocks") or []
        if not isinstance(raw_blocks, list):
            raise ValueError("JSON coverage must contain a 'coverage' or 'blocks' array")

        for entry in raw_blocks[:_MAX_COVERAGE_ENTRIES]:
            if not isinstance(entry, dict):
                continue
            addr = entry.get("address") or entry.get("start") or entry.get("addr")
            size = entry.get("size") or entry.get("length", 1)
            if addr is None:
                continue
            try:
                if isinstance(addr, str):
                    addr = int(addr, 16) if addr.startswith("0x") else int(addr)
                elif not isinstance(addr, (int, float)):
                    continue
                if isinstance(size, str):
                    size = int(size, 16) if size.startswith("0x") else int(size)
                elif not isinstance(size, (int, float)):
                    size = 1
                blocks.append({"address": int(addr), "size": int(size)})
            except (ValueError, TypeError, OverflowError):
                continue

        modules = obj.get("modules", [])

    elif isinstance(obj, list):
        # Format: [{start, end}, ...] or [{address, size}, ...]
        for entry in obj[:_MAX_COVERAGE_ENTRIES]:
            if not isinstance(entry, dict):
                continue
            if "start" in entry and "end" in entry:
                start = entry["start"]
                end = entry["end"]
                if isinstance(start, str):
                    start = int(start, 16)
                if isinstance(end, str):
                    end = int(end, 16)
                blocks.append({"address": int(start), "size": int(end) - int(start)})
            elif "address" in entry:
                addr = entry["address"]
                size = entry.get("size", 1)
                if isinstance(addr, str):
                    addr = int(addr, 16)
                blocks.append({"address": int(addr), "size": int(size)})
        modules = []
    else:
        raise ValueError("Unsupported JSON coverage structure")

    return {
        "format": "json",
        "modules": modules[:_MAX_MODULES] if isinstance(modules, list) else [],
        "blocks": blocks,
        "block_count": len(blocks),
        "module_count": len(modules) if isinstance(modules, list) else 0,
    }


# ---------------------------------------------------------------------------
# Generic CSV coverage parser
# ---------------------------------------------------------------------------

def _parse_csv_coverage(data: bytes) -> Dict[str, Any]:
    """Parse CSV coverage (address,size per line).

    Format: one block per line, hex or decimal addresses.
        0x401000,16
        0x401020,8
    """
    text = data.decode("utf-8", errors="replace")
    blocks = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("address"):
            continue  # Skip comments and header
        parts = line.split(",")
        if len(parts) < 1:
            continue
        try:
            addr_str = parts[0].strip()
            addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
            size = 1
            if len(parts) >= 2:
                size_str = parts[1].strip()
                size = int(size_str, 16) if size_str.startswith("0x") else int(size_str)
            blocks.append({"address": addr, "size": max(1, size)})
        except (ValueError, OverflowError):
            continue
        if len(blocks) >= _MAX_COVERAGE_ENTRIES:
            break

    return {
        "format": "csv",
        "modules": [],
        "blocks": blocks,
        "block_count": len(blocks),
        "module_count": 0,
    }


# ---------------------------------------------------------------------------
# Format auto-detection
# ---------------------------------------------------------------------------

def _detect_coverage_format(data: bytes) -> str:
    """Detect coverage file format from content."""
    if data[:7] == b"DRCOV " or b"BB Table:" in data[:4096]:
        return "drcov"
    # Try JSON
    stripped = data.lstrip()
    if stripped[:1] in (b"{", b"["):
        return "json"
    # Default to CSV
    return "csv"


# ---------------------------------------------------------------------------
# Coverage overlay on function map
# ---------------------------------------------------------------------------

def _overlay_coverage_on_functions(
    blocks: List[Dict[str, Any]],
    image_base: int = 0,
) -> Dict[str, Any]:
    """Overlay coverage blocks onto the loaded binary's function map.

    Returns coverage statistics and per-function coverage status.
    """
    from arkana.config import ANGR_AVAILABLE

    # Build a set of covered block start addresses for fast lookup.
    # Only store block start addresses (not every byte) to bound memory.
    _MAX_COVERED_ADDRS = 1_000_000
    covered_addrs = set()
    for block in blocks:
        addr = block["address"]
        covered_addrs.add(addr)
        if len(covered_addrs) >= _MAX_COVERED_ADDRS:
            break

    # Overlay on angr CFG functions if available
    _MAX_OVERLAY_FUNCTIONS = 50_000
    covered_functions = []
    uncovered_functions = []
    covered_count = 0
    uncovered_count = 0

    if ANGR_AVAILABLE and state.angr_cfg is not None:
        try:
            func_iter = 0
            for addr, func in state.angr_cfg.functions.items():
                func_iter += 1
                if func_iter > _MAX_OVERLAY_FUNCTIONS:
                    break
                if func.is_simprocedure or func.is_syscall:
                    continue
                # Check if any block in the function was covered
                func_covered = False
                try:
                    for block in func.blocks:
                        if block.addr in covered_addrs:
                            func_covered = True
                            break
                except Exception:
                    func_covered = addr in covered_addrs

                entry = {
                    "address": hex(addr),
                    "name": func.name,
                    "size": func.size,
                }
                if func_covered:
                    covered_count += 1
                    if len(covered_functions) < 50:
                        covered_functions.append(entry)
                else:
                    uncovered_count += 1
                    if len(uncovered_functions) < 50:
                        uncovered_functions.append(entry)
        except Exception as e:
            logger.debug("Coverage overlay failed: %s", e)

    total = covered_count + uncovered_count
    coverage_pct = round(100 * covered_count / total, 1) if total > 0 else 0

    return {
        "total_functions": total,
        "covered_functions": covered_count,
        "uncovered_functions": uncovered_count,
        "coverage_percent": coverage_pct,
        "top_uncovered": uncovered_functions[:50],
        "top_covered": covered_functions[:50],
    }


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------

@tool_decorator
async def import_coverage_data(
    ctx: Context,
    file_path: str,
    format: str = "auto",
) -> Dict[str, Any]:
    """[Phase: deep-dive] Import code coverage data from DBI tools.

    Parses DynamoRIO drcov, Frida/Lighthouse JSON, or CSV coverage files
    and overlays the coverage onto the loaded binary's function map. This
    identifies which functions were executed during dynamic analysis and
    which remain uncovered.

    ---compact: import drcov/JSON/CSV coverage data | overlay on function map | needs: file

    Supported formats:
        - ``drcov`` — DynamoRIO binary coverage (also from Frida Stalker drcov output)
        - ``json`` — Lighthouse/Frida JSON (``{"coverage": [{"address": ..., "size": ...}]}``)
        - ``csv`` — Simple ``address,size`` per line (hex or decimal)
        - ``auto`` — Detect format from file content (default)

    When to use: After collecting coverage data from an external DBI tool
    (DynamoRIO, Frida Stalker, Intel PIN) or emulator trace. Helps focus
    analysis on uncovered code paths that may contain hidden functionality.

    Next steps: decompile_function_with_angr() on uncovered functions,
    find_path_to_address() to reach uncovered code symbolically.

    Args:
        file_path: Path to the coverage file.
        format: Coverage format — 'auto' (default), 'drcov', 'json', or 'csv'.
    """
    await ctx.info(f"Importing coverage data from {os.path.basename(file_path)}")
    _check_pe_loaded("import_coverage_data")

    resolved = os.path.realpath(file_path)
    state.check_path_allowed(resolved)

    if not os.path.isfile(resolved):
        return {"error": f"Coverage file not found: {file_path}"}

    file_size = os.path.getsize(resolved)
    if file_size > _MAX_COVERAGE_FILE_SIZE:
        return {"error": f"Coverage file too large ({file_size} bytes). Maximum is {_MAX_COVERAGE_FILE_SIZE}."}
    if file_size == 0:
        return {"error": "Coverage file is empty."}

    def _parse():
        with open(resolved, "rb") as f:
            data = f.read()

        fmt = format.lower().strip()  # noqa: A002 (shadows builtin, but is MCP API name)
        if fmt == "auto":
            fmt = _detect_coverage_format(data)

        if fmt == "drcov":
            parsed = _parse_drcov(data)
        elif fmt == "json":
            parsed = _parse_json_coverage(data)
        elif fmt == "csv":
            parsed = _parse_csv_coverage(data)
        else:
            return {"error": f"Unsupported format: {format!r}. Use 'auto', 'drcov', 'json', or 'csv'."}

        # Get image base for address resolution
        image_base = 0
        pe_obj = state.pe_object
        if pe_obj is not None and hasattr(pe_obj, "OPTIONAL_HEADER"):
            image_base = pe_obj.OPTIONAL_HEADER.ImageBase

        # Overlay on function map
        overlay = _overlay_coverage_on_functions(parsed["blocks"], image_base)

        # Cache on state
        state._cached_coverage = {
            "blocks": parsed["blocks"],
            "modules": parsed.get("modules", []),
            "format": parsed["format"],
            "source_file": os.path.basename(resolved),
            "overlay": overlay,
        }

        return {
            "status": "success",
            "format_detected": parsed["format"],
            "blocks_imported": parsed["block_count"],
            "modules": parsed.get("modules", [])[:20],
            "module_count": parsed.get("module_count", 0),
            "coverage": overlay,
            "source_file": os.path.basename(resolved),
            "next_step": (
                "Use get_coverage_summary() for detailed stats, or "
                "decompile uncovered functions to find hidden functionality."
            ),
        }

    result = await asyncio.to_thread(_parse)
    if "error" in result:
        return result
    return await _check_mcp_response_size(ctx, result, "import_coverage_data")


@tool_decorator
async def get_coverage_summary(
    ctx: Context,
    show_uncovered: int = 20,
    show_covered: int = 10,
) -> Dict[str, Any]:
    """[Phase: deep-dive] Summarise imported code coverage data.

    Shows coverage statistics, top uncovered functions (potential hidden
    functionality), and top covered functions. Requires prior
    import_coverage_data() call.

    ---compact: coverage stats + uncovered function list | needs: import_coverage_data

    When to use: After import_coverage_data() to review what the dynamic
    analysis did and did not exercise.

    Args:
        show_uncovered: Number of uncovered functions to show (default 20).
        show_covered: Number of covered functions to show (default 10).
    """
    cached = getattr(state, "_cached_coverage", None)
    if not cached:
        return {
            "error": "No coverage data loaded. Call import_coverage_data() first.",
            "hint": "Collect coverage using DynamoRIO (drcov), Frida Stalker, or "
                    "generate_frida_stalker_script() and import the results.",
        }

    show_uncovered = max(1, min(show_uncovered, MAX_TOOL_LIMIT))
    show_covered = max(1, min(show_covered, MAX_TOOL_LIMIT))

    overlay = cached.get("overlay", {})

    return {
        "source_file": cached.get("source_file", "unknown"),
        "format": cached.get("format", "unknown"),
        "total_blocks": len(cached.get("blocks", [])),
        "total_functions": overlay.get("total_functions", 0),
        "covered_functions": overlay.get("covered_functions", 0),
        "uncovered_functions": overlay.get("uncovered_functions", 0),
        "coverage_percent": overlay.get("coverage_percent", 0),
        "top_uncovered": overlay.get("top_uncovered", [])[:show_uncovered],
        "top_covered": overlay.get("top_covered", [])[:show_covered],
        "next_step": (
            "Decompile uncovered functions to look for hidden functionality: "
            "decompile_function_with_angr(address) or batch_decompile(addresses)."
        ),
    }
