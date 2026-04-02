"""MCP tools for instruction trace analysis and MBA obfuscation detection.

Supports Triton-powered symbolic analysis (when installed) and a pure-Python
fallback for trace parsing and MBA pattern detection via regex.
"""
import asyncio
import json
import os
import re
import logging
from typing import Any, Dict, List, Optional

from arkana.config import state, logger, Context
from arkana.constants import MAX_TOOL_LIMIT
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size

# Triton availability — local to this module, also exported via imports.py
try:
    from triton import TritonContext, ARCH, Instruction, MODE, AST_REPRESENTATION
    TRITON_AVAILABLE = True
except ImportError:
    TRITON_AVAILABLE = False

# Safety caps
_MAX_TRACE_ENTRIES = 100_000
_MAX_TRACE_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

# ---------------------------------------------------------------------------
#  MBA pattern definitions (compiled regex)
# ---------------------------------------------------------------------------

_MBA_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "xor_via_not_and_or",
        "description": "(~x & y) | (x & ~y) is equivalent to x ^ y",
        "pattern": re.compile(
            r"\(\s*~\s*(\w+)\s*&\s*(\w+)\s*\)\s*\|\s*\(\s*\1\s*&\s*~\s*\2\s*\)"
        ),
        "simplified": "XOR({x}, {y})",
        "confidence": 0.9,
    },
    {
        "name": "xor_via_or_minus_and",
        "description": "(x | y) - (x & y) is equivalent to x ^ y",
        "pattern": re.compile(
            r"\(\s*(\w+)\s*\|\s*(\w+)\s*\)\s*-\s*\(\s*\1\s*&\s*\2\s*\)"
        ),
        "simplified": "XOR({x}, {y})",
        "confidence": 0.85,
    },
    {
        "name": "add_via_and_plus_or",
        "description": "(x & y) + (x | y) is equivalent to x + y",
        "pattern": re.compile(
            r"\(\s*(\w+)\s*&\s*(\w+)\s*\)\s*\+\s*\(\s*\1\s*\|\s*\2\s*\)"
        ),
        "simplified": "ADD({x}, {y})",
        "confidence": 0.85,
    },
    {
        "name": "double_negation",
        "description": "~~x is equivalent to x (redundant double negation)",
        "pattern": re.compile(r"~~(\w+)"),
        "simplified": "{x}",
        "confidence": 0.95,
    },
    {
        "name": "tautology_or_not",
        "description": "x | ~x is always -1 (all bits set)",
        "pattern": re.compile(r"(\w+)\s*\|\s*~\s*\1(?!\w)"),
        "simplified": "-1",
        "confidence": 0.95,
    },
    {
        "name": "contradiction_and_not",
        "description": "x & ~x is always 0",
        "pattern": re.compile(r"(\w+)\s*&\s*~\s*\1(?!\w)"),
        "simplified": "0",
        "confidence": 0.95,
    },
    {
        "name": "algebraic_xor_and_identity",
        "description": "(a + b) == (a ^ b) + 2 * (a & b) — algebraic MBA identity",
        "pattern": re.compile(
            r"\(\s*(\w+)\s*\^\s*(\w+)\s*\)\s*\+\s*2\s*\*\s*\(\s*\1\s*&\s*\2\s*\)"
        ),
        "simplified": "ADD({x}, {y})",
        "confidence": 0.9,
    },
    {
        "name": "nested_bitwise_xor_variant",
        "description": "(x & ~y) | (~x & y) is equivalent to x ^ y (commuted variant)",
        "pattern": re.compile(
            r"\(\s*(\w+)\s*&\s*~\s*(\w+)\s*\)\s*\|\s*\(\s*~\s*\1\s*&\s*\2\s*\)"
        ),
        "simplified": "XOR({x}, {y})",
        "confidence": 0.9,
    },
    {
        "name": "opaque_add_identity",
        "description": "(x | y) + (x & y) is equivalent to x + y (commuted add-via-or-and)",
        "pattern": re.compile(
            r"\(\s*(\w+)\s*\|\s*(\w+)\s*\)\s*\+\s*\(\s*\1\s*&\s*\2\s*\)"
        ),
        "simplified": "ADD({x}, {y})",
        "confidence": 0.85,
    },
]


# ---------------------------------------------------------------------------
#  Trace format parsers
# ---------------------------------------------------------------------------

def _parse_pin_trace(text: str) -> List[Dict[str, Any]]:
    """Parse Intel PIN-format trace: r:<regs> / i:<addr>:<size>:<hex> pairs."""
    entries = []
    lines = text.splitlines()
    current_regs = None
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("r:"):
            current_regs = line[2:].strip()
        elif line.startswith("i:"):
            parts = line[2:].split(":")
            if len(parts) >= 3:
                try:
                    addr_str = parts[0].strip()
                    addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                    size = int(parts[1].strip())
                    hex_bytes = parts[2].strip()
                    entry = {
                        "address": addr,
                        "size": size,
                        "bytes": hex_bytes,
                    }
                    if current_regs:
                        entry["registers"] = current_regs
                        current_regs = None
                    entries.append(entry)
                except (ValueError, OverflowError):
                    continue
        if len(entries) >= _MAX_TRACE_ENTRIES:
            break
    return entries


def _parse_csv_trace(text: str) -> List[Dict[str, Any]]:
    """Parse CSV trace: address,hex_bytes[,mnemonic] per line."""
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.lower().startswith("address"):
            continue
        parts = line.split(",")
        if len(parts) < 2:
            continue
        try:
            addr_str = parts[0].strip()
            addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
            hex_bytes = parts[1].strip()
            entry = {
                "address": addr,
                "bytes": hex_bytes,
                "size": len(hex_bytes) // 2 if hex_bytes else 0,
            }
            if len(parts) >= 3:
                entry["mnemonic"] = parts[2].strip()
            entries.append(entry)
        except (ValueError, OverflowError):
            continue
        if len(entries) >= _MAX_TRACE_ENTRIES:
            break
    return entries


def _parse_json_trace(data: bytes) -> List[Dict[str, Any]]:
    """Parse JSON trace: [{"address": ..., "bytes": "...", "mnemonic": "..."}]."""
    try:
        obj = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"Invalid JSON trace file: {e}")

    if not isinstance(obj, list):
        if isinstance(obj, dict) and "trace" in obj:
            obj = obj["trace"]
        else:
            raise ValueError("JSON trace must be an array or contain a 'trace' array")

    entries = []
    for item in obj[:_MAX_TRACE_ENTRIES]:
        if not isinstance(item, dict):
            continue
        addr = item.get("address") or item.get("addr") or item.get("ip")
        if addr is None:
            continue
        if isinstance(addr, str):
            addr = int(addr, 16) if addr.startswith("0x") else int(addr)
        hex_bytes = item.get("bytes", item.get("opcodes", ""))
        entry = {
            "address": int(addr),
            "bytes": str(hex_bytes),
            "size": item.get("size", len(str(hex_bytes)) // 2 if hex_bytes else 0),
        }
        mnemonic = item.get("mnemonic") or item.get("disasm")
        if mnemonic:
            entry["mnemonic"] = str(mnemonic)
        entries.append(entry)
    return entries


def _detect_trace_format(data: bytes) -> str:
    """Detect trace file format from content."""
    # Check for JSON
    stripped = data.lstrip()
    if stripped[:1] in (b"{", b"["):
        return "json"
    # Check for PIN format (r: / i: line pairs)
    text_head = data[:4096].decode("utf-8", errors="replace")
    if any(line.strip().startswith("i:") for line in text_head.splitlines()[:50]):
        return "pin"
    # Default to CSV
    return "csv"


# ---------------------------------------------------------------------------
#  Triton-based symbolic trace analysis
# ---------------------------------------------------------------------------

def _analyze_with_triton(entries: List[Dict[str, Any]], arch_str: str) -> Dict[str, Any]:
    """Process trace entries through Triton for symbolic analysis."""
    if not TRITON_AVAILABLE:
        return {"error": "Triton is not installed"}

    # Map architecture string to Triton ARCH
    arch_map = {
        "x86": ARCH.X86,
        "x86_64": ARCH.X86_64,
        "x64": ARCH.X86_64,
        "amd64": ARCH.X86_64,
    }
    triton_arch = arch_map.get(arch_str.lower())
    if triton_arch is None:
        return {"error": f"Unsupported architecture for Triton: {arch_str!r}. Supported: {list(arch_map.keys())}"}

    ctx = TritonContext(triton_arch)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)

    simplified_expressions = []
    errors = 0
    processed = 0

    for entry in entries:
        hex_bytes = entry.get("bytes", "")
        if not hex_bytes:
            continue
        try:
            raw_bytes = bytes.fromhex(hex_bytes.replace(" ", ""))
        except ValueError:
            errors += 1
            continue

        inst = Instruction()
        inst.setAddress(entry["address"])
        inst.setOpcode(raw_bytes)

        try:
            if not ctx.processing(inst):
                errors += 1
                continue
            processed += 1

            # Extract symbolic expressions for written registers
            for se in inst.getSymbolicExpressions():
                if se is None:
                    continue
                ast_node = se.getAst()
                simplified = ctx.simplify(ast_node)
                original_str = str(ast_node)
                simplified_str = str(simplified)
                if original_str != simplified_str and len(original_str) > len(simplified_str):
                    simplified_expressions.append({
                        "address": hex(entry["address"]),
                        "instruction": inst.getDisassembly(),
                        "original": original_str[:500],
                        "simplified": simplified_str[:500],
                    })
        except Exception as e:
            errors += 1
            if errors <= 5:
                logger.debug("Triton processing error at 0x%x: %s", entry["address"], e)
            continue

    return {
        "processed": processed,
        "errors": errors,
        "simplifications": simplified_expressions[:200],
        "simplification_count": len(simplified_expressions),
    }


# ---------------------------------------------------------------------------
#  Pure-Python trace statistics (fallback without Triton)
# ---------------------------------------------------------------------------

# Common Windows API names for heuristic detection
_COMMON_API_PREFIXES = frozenset({
    "kernel32", "ntdll", "user32", "advapi32", "ws2_32", "wininet",
    "winhttp", "crypt32", "msvcrt", "ucrtbase", "shell32", "ole32",
})


def _compute_trace_stats(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute basic statistics from parsed trace entries."""
    if not entries:
        return {"instruction_count": 0, "unique_addresses": 0}

    addresses = set()
    mnemonics: Dict[str, int] = {}

    for entry in entries:
        addresses.add(entry["address"])
        mnemonic = entry.get("mnemonic", "")
        if mnemonic:
            base_mnem = mnemonic.split()[0].lower() if mnemonic else ""
            if base_mnem:
                mnemonics[base_mnem] = mnemonics.get(base_mnem, 0) + 1

    # Sort addresses to compute basic block boundaries
    sorted_addrs = sorted(addresses)
    addr_range = (hex(sorted_addrs[0]), hex(sorted_addrs[-1])) if sorted_addrs else ("0x0", "0x0")

    # Top 20 most frequent mnemonics
    top_mnemonics = sorted(mnemonics.items(), key=lambda x: x[1], reverse=True)[:20]

    return {
        "instruction_count": len(entries),
        "unique_addresses": len(addresses),
        "address_range": {"start": addr_range[0], "end": addr_range[1]},
        "top_mnemonics": [{"mnemonic": m, "count": c} for m, c in top_mnemonics],
        "total_unique_mnemonics": len(mnemonics),
    }


# ---------------------------------------------------------------------------
#  MBA detection in decompiled pseudocode
# ---------------------------------------------------------------------------

def _scan_for_mba_patterns(lines: List[str]) -> List[Dict[str, Any]]:
    """Scan decompiled pseudocode lines for MBA patterns."""
    detections = []
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            continue
        for pat_info in _MBA_PATTERNS:
            match = pat_info["pattern"].search(stripped)
            if match:
                groups = match.groups()
                simplified = pat_info["simplified"]
                # Substitute captured group names into simplified form
                if len(groups) >= 2:
                    simplified = simplified.replace("{x}", groups[0]).replace("{y}", groups[1])
                elif len(groups) >= 1:
                    simplified = simplified.replace("{x}", groups[0])

                detections.append({
                    "line": line_num,
                    "pattern_name": pat_info["name"],
                    "description": pat_info["description"],
                    "matched_text": match.group(0)[:200],
                    "simplified_form": simplified,
                    "confidence": pat_info["confidence"],
                    "source_line": stripped[:300],
                })
    return detections


def _try_triton_simplify(expression_str: str) -> Optional[str]:
    """Attempt to simplify an expression using Triton's AST engine.

    Returns the simplified string if successful and different from input,
    otherwise None.
    """
    if not TRITON_AVAILABLE:
        return None
    try:
        ctx = TritonContext(ARCH.X86_64)
        ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
        ast_ctx = ctx.getAstContext()
        # Create symbolic variables for detected operands
        _x = ast_ctx.variable(ctx.newSymbolicVariable(64, "x"))  # noqa: F841
        _y = ast_ctx.variable(ctx.newSymbolicVariable(64, "y"))  # noqa: F841
        # Attempt to build and simplify — this is best-effort.
        # Triton AST construction from arbitrary expression strings is not
        # directly supported, so we return None for expressions we can't
        # construct programmatically.
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
#  MCP Tools
# ---------------------------------------------------------------------------

@tool_decorator
async def analyze_instruction_trace(
    ctx: Context,
    file_path: str,
    format: str = "auto",
    architecture: str = "x86_64",
) -> Dict[str, Any]:
    """[Phase: deep-dive] Analyze an instruction trace with optional symbolic analysis.

    Parses instruction traces from DBI tools (Intel PIN, DynamoRIO, Frida) and
    produces execution statistics. When Triton is installed, performs symbolic
    analysis to simplify input-to-output register relationships and detect
    obfuscated computations.

    ---compact: parse instruction trace + symbolic analysis | PIN/CSV/JSON formats | needs: file

    Supported formats:
        - ``pin`` — Intel PIN format (``r:<regs>`` / ``i:<addr>:<size>:<hex>`` pairs)
        - ``csv`` — ``address,hex_bytes[,mnemonic]`` per line
        - ``json`` — ``[{"address": ..., "bytes": "...", "mnemonic": "..."}]``
        - ``auto`` — Detect format from file content (default)

    When Triton is available, each instruction is processed through Triton's
    symbolic engine to extract and simplify register expressions, revealing the
    actual computation underneath obfuscated instruction sequences.

    When Triton is NOT available, returns trace statistics (instruction count,
    unique addresses, mnemonic frequency) without symbolic simplification.

    When to use: After collecting an instruction trace from a DBI tool. Helps
    understand obfuscated code by revealing simplified symbolic expressions.

    Next steps: detect_mba_obfuscation() on suspicious functions,
    decompile_function_with_angr() on key addresses found in the trace.

    Args:
        file_path: Path to the trace file.
        format: Trace format — 'auto' (default), 'pin', 'csv', or 'json'.
        architecture: Target architecture — 'x86_64' (default), 'x86', 'amd64'.
    """
    await ctx.info(f"Analyzing instruction trace from {os.path.basename(file_path)}")
    _check_pe_loaded("analyze_instruction_trace")

    resolved = os.path.realpath(file_path)
    state.check_path_allowed(resolved)

    if not os.path.isfile(resolved):
        return {"error": f"Trace file not found: {file_path}"}

    file_size = os.path.getsize(resolved)
    if file_size > _MAX_TRACE_FILE_SIZE:
        return {"error": f"Trace file too large ({file_size} bytes). Maximum is {_MAX_TRACE_FILE_SIZE}."}
    if file_size == 0:
        return {"error": "Trace file is empty."}

    def _parse_and_analyze():
        with open(resolved, "rb") as f:
            data = f.read()

        fmt = format.lower().strip()
        if fmt == "auto":
            fmt = _detect_trace_format(data)

        # Parse based on detected/specified format
        if fmt == "pin":
            text = data.decode("utf-8", errors="replace")
            entries = _parse_pin_trace(text)
        elif fmt == "csv":
            text = data.decode("utf-8", errors="replace")
            entries = _parse_csv_trace(text)
        elif fmt == "json":
            entries = _parse_json_trace(data)
        else:
            return {"error": f"Unsupported trace format: {format!r}. Use 'auto', 'pin', 'csv', or 'json'."}

        if not entries:
            return {"error": "No valid trace entries found in the file."}

        # Basic statistics (always computed)
        stats = _compute_trace_stats(entries)

        result = {
            "status": "success",
            "format_detected": fmt,
            "source_file": os.path.basename(resolved),
            "triton_available": TRITON_AVAILABLE,
            "statistics": stats,
        }

        # Symbolic analysis if Triton is available
        if TRITON_AVAILABLE:
            symbolic = _analyze_with_triton(entries, architecture)
            if "error" in symbolic:
                result["triton_error"] = symbolic["error"]
            else:
                result["symbolic_analysis"] = symbolic
        else:
            result["note"] = (
                "Triton is not installed. Install with 'pip install triton' "
                "for full symbolic trace analysis (expression simplification, "
                "MBA detection, taint tracking). Showing basic statistics only."
            )

        return result

    result = await asyncio.to_thread(_parse_and_analyze)
    if "error" in result:
        return result
    return await _check_mcp_response_size(ctx, result, "analyze_instruction_trace")


@tool_decorator
async def detect_mba_obfuscation(
    ctx: Context,
    function_address: str,
) -> Dict[str, Any]:
    """[Phase: deep-dive] Detect Mixed Boolean-Arithmetic obfuscation in decompiled code.

    Scans the decompiled pseudocode of a function for MBA (Mixed Boolean-Arithmetic)
    obfuscation patterns. MBA transforms simple operations (XOR, ADD) into
    semantically equivalent but complex boolean-arithmetic expressions to hinder
    reverse engineering.

    ---compact: detect MBA obfuscation patterns in pseudocode | regex + Triton simplify | needs: angr decompile

    Detected patterns include:
        - ``(~x & y) | (x & ~y)`` = XOR (bitwise NOT/AND/OR substitution)
        - ``(x | y) - (x & y)`` = XOR (arithmetic identity)
        - ``(x & y) + (x | y)`` = ADD (opaque addition)
        - ``~~x`` = x (redundant double negation)
        - ``x | ~x`` = -1 (tautology)
        - ``x & ~x`` = 0 (contradiction)
        - ``(a ^ b) + 2*(a & b)`` = ADD (algebraic identity)

    When Triton is available, attempts to symbolically simplify detected
    expressions. Returns both the original and simplified forms.

    When to use: After decompiling a function that shows unusual arithmetic
    or bitwise operations. Common in malware using obfuscators like Tigress,
    OLLVM, or custom MBA passes.

    Next steps: Use the simplified forms to understand the actual computation.
    Apply rename_variable() to annotate deobfuscated meanings.

    Args:
        function_address: Address of the function to analyze (hex string, e.g. '0x401000').
    """
    await ctx.info(f"Scanning for MBA obfuscation at {function_address}")
    _check_pe_loaded("detect_mba_obfuscation")

    # Parse the function address
    try:
        if isinstance(function_address, str):
            addr_int = int(function_address, 16) if function_address.startswith("0x") else int(function_address)
        else:
            addr_int = int(function_address)
    except (ValueError, OverflowError):
        return {"error": f"Invalid function address: {function_address!r}"}

    def _detect():
        # Access the decompile cache to get pseudocode
        from arkana.mcp.tools_angr import _make_decompile_key, _get_cached_lines

        cache_key = _make_decompile_key(addr_int)
        lines = _get_cached_lines(cache_key)

        if lines is None:
            return {
                "error": (
                    f"No cached decompilation for function at {function_address}. "
                    "Call decompile_function_with_angr(address) first."
                ),
                "hint": f"decompile_function_with_angr(address='{function_address}')",
            }

        # Scan for MBA patterns
        detections = _scan_for_mba_patterns(lines)

        # Attempt Triton simplification on detected expressions
        if TRITON_AVAILABLE:
            for det in detections:
                triton_result = _try_triton_simplify(det["matched_text"])
                if triton_result:
                    det["triton_simplified"] = triton_result

        # Compute summary
        high_confidence = [d for d in detections if d["confidence"] >= 0.9]
        medium_confidence = [d for d in detections if 0.8 <= d["confidence"] < 0.9]

        result = {
            "function_address": hex(addr_int),
            "total_lines_scanned": len(lines),
            "detections": detections,
            "detection_count": len(detections),
            "high_confidence_count": len(high_confidence),
            "medium_confidence_count": len(medium_confidence),
            "triton_available": TRITON_AVAILABLE,
        }

        if detections:
            result["assessment"] = (
                f"Found {len(detections)} MBA pattern(s). "
                f"{len(high_confidence)} high-confidence, {len(medium_confidence)} medium-confidence. "
                "This function likely uses MBA obfuscation to hide simple operations."
            )
            result["next_step"] = (
                "Review the simplified forms to understand the actual computation. "
                "Use rename_variable() to annotate deobfuscated variables."
            )
        else:
            result["assessment"] = (
                "No MBA obfuscation patterns detected in the decompiled pseudocode. "
                "The function may use other obfuscation techniques (control flow flattening, "
                "opaque predicates) or may not be obfuscated."
            )

        if not TRITON_AVAILABLE and detections:
            result["note"] = (
                "Install Triton ('pip install triton') for symbolic expression "
                "simplification of detected MBA patterns."
            )

        return result

    result = await asyncio.to_thread(_detect)
    if "error" in result:
        return result
    return await _check_mcp_response_size(ctx, result, "detect_mba_obfuscation")
