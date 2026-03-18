"""MCP tools for .NET deobfuscation, obfuscation detection, and C# decompilation.

Tools:
    detect_dotnet_obfuscation  — pure-Python obfuscation detection via dnfile metadata
    dotnet_deobfuscate         — orchestrates de4dot-cex and NETReactorSlayer (subprocess)
    dotnet_decompile           — C# source recovery via ilspycmd/ILSpy (subprocess)
"""
import asyncio
import math
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from arkana.config import (
    state, logger, Context,
    DNFILE_AVAILABLE,
    DE4DOT_AVAILABLE, DE4DOT_IMPORT_ERROR,
    NETREACTORSLAYER_AVAILABLE, NETREACTORSLAYER_IMPORT_ERROR,
    ILSPYCMD_AVAILABLE, ILSPYCMD_IMPORT_ERROR,
    _DE4DOT_PATH, _check_de4dot_available,
    _NETREACTORSLAYER_PATH, _check_netreactorslayer_available,
    _ILSPYCMD_PATH, _check_ilspycmd_available,
)
from arkana.mcp.server import tool_decorator, _check_mcp_response_size
from arkana.mcp._format_helpers import _get_filepath
from arkana.mcp._refinery_helpers import _write_output_and_register_artifact
from arkana.constants import (
    DOTNET_DEOBFUSCATE_TIMEOUT, DOTNET_DECOMPILE_TIMEOUT,
    DOTNET_DECOMPILE_MAX_OUTPUT_LINES, MAX_TOOL_LIMIT,
)

if DNFILE_AVAILABLE:
    import dnfile


# ---------------------------------------------------------------------------
#  Obfuscator signature database
# ---------------------------------------------------------------------------

_OBFUSCATOR_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "confuserex": {
        "name": "ConfuserEx",
        "custom_attributes": ["ConfusedByAttribute", "ConfuserEx"],
        "resource_patterns": [r"ConfuserEx"],
        "recommended_tool": "de4dot",
    },
    "dotnet_reactor": {
        "name": ".NET Reactor",
        "resource_patterns": [r"__\$", r"ReactorHelper", r"\.Reactored"],
        "custom_attributes": [".NET Reactor"],
        "recommended_tool": "reactor_slayer",
    },
    "smartassembly": {
        "name": "SmartAssembly",
        "custom_attributes": [
            "PoweredByAttribute", "SmartAssembly.Attributes",
            "SmartAssembly",
        ],
        "recommended_tool": "de4dot",
    },
    "dotfuscator": {
        "name": "Dotfuscator",
        "custom_attributes": [
            "DotfuscatorAttribute", "Dotfuscated",
            "PreEmptive.SoS.Dotfuscator",
        ],
        "recommended_tool": "de4dot",
    },
    "babel": {
        "name": "Babel .NET",
        "custom_attributes": ["BabelAttribute", "Babel.Licensing"],
        "resource_patterns": [r"Babel"],
        "recommended_tool": "de4dot",
    },
    "crypto_obfuscator": {
        "name": "Crypto Obfuscator",
        "custom_attributes": ["CryptoObfuscator"],
        "resource_patterns": [r"CryptoObfuscator"],
        "recommended_tool": "de4dot",
    },
    "agile": {
        "name": "Agile.NET (CliSecure)",
        "custom_attributes": ["CliSecureAttribute"],
        "recommended_tool": "de4dot",
    },
    "goliath": {
        "name": "Goliath.NET",
        "custom_attributes": ["GoliathAttribute", "Goliath.NET"],
        "recommended_tool": "de4dot",
    },
    "eazfuscator": {
        "name": "Eazfuscator.NET",
        "custom_attributes": ["EazAttribute", "Eazfuscator"],
        "recommended_tool": "de4dot",
    },
    "phoenix_protector": {
        "name": "Phoenix Protector",
        "custom_attributes": ["PhoenixAttribute"],
        "recommended_tool": "de4dot",
    },
}


# ---------------------------------------------------------------------------
#  Pure-Python detection helpers
# ---------------------------------------------------------------------------

def _calc_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string. Higher = more random."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _calc_name_entropy(names: List[str]) -> float:
    """Average Shannon entropy across a list of names."""
    if not names:
        return 0.0
    return sum(_calc_shannon_entropy(n) for n in names) / len(names)


def _is_non_ascii(name: str) -> bool:
    """Check if a name contains non-ASCII characters (common in obfuscated .NET)."""
    try:
        name.encode("ascii")
        return False
    except (UnicodeEncodeError, UnicodeDecodeError):
        return True


def _match_custom_attributes(
    attribute_names: List[str],
    signatures: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Match custom attribute names against known obfuscator signatures."""
    detections: List[Dict[str, Any]] = []
    for sig_id, sig in signatures.items():
        for pattern in sig.get("custom_attributes", []):
            pattern_lower = pattern.lower()
            for attr in attribute_names:
                if pattern_lower in attr.lower():
                    detections.append({
                        "obfuscator": sig["name"],
                        "confidence": "high",
                        "evidence": f"Custom attribute match: '{attr}' matches '{pattern}'",
                        "recommended_tool": sig.get("recommended_tool", "de4dot"),
                        "sig_id": sig_id,
                    })
                    break  # One match per signature is enough
    return detections


def _match_resource_patterns(
    resource_names: List[str],
    signatures: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Match resource names against known obfuscator patterns."""
    detections: List[Dict[str, Any]] = []
    for sig_id, sig in signatures.items():
        for pattern in sig.get("resource_patterns", []):
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
            except re.error:
                continue
            for rname in resource_names:
                if compiled.search(rname):
                    detections.append({
                        "obfuscator": sig["name"],
                        "confidence": "medium",
                        "evidence": f"Resource name match: '{rname}' matches /{pattern}/",
                        "recommended_tool": sig.get("recommended_tool", "de4dot"),
                        "sig_id": sig_id,
                    })
                    break
    return detections


def _classify_obfuscator(
    detections: List[Dict[str, Any]],
    generic_indicators: Dict[str, Any],
) -> Tuple[bool, List[Dict[str, Any]]]:
    """Classify whether the assembly is obfuscated and deduplicate detections."""
    # Deduplicate by sig_id, keeping highest confidence
    seen: Dict[str, Dict[str, Any]] = {}
    confidence_rank = {"high": 3, "medium": 2, "low": 1}
    for det in detections:
        sig_id = det.get("sig_id", det["obfuscator"])
        existing = seen.get(sig_id)
        if existing is None or confidence_rank.get(det["confidence"], 0) > confidence_rank.get(existing["confidence"], 0):
            seen[sig_id] = det
    unique = list(seen.values())
    # Remove internal sig_id from output
    for d in unique:
        d.pop("sig_id", None)

    # Determine overall obfuscation status
    is_obfuscated = bool(unique)

    # Also flag as obfuscated on strong generic indicators
    if not is_obfuscated:
        non_ascii_pct = generic_indicators.get("non_ascii_name_pct", 0)
        avg_entropy = generic_indicators.get("type_name_entropy", 0)
        if non_ascii_pct > 50 or avg_entropy > 4.5:
            is_obfuscated = True
            unique.append({
                "obfuscator": "Unknown (generic indicators)",
                "confidence": "low",
                "evidence": (
                    f"High name entropy ({avg_entropy:.2f}) "
                    f"and/or non-ASCII names ({non_ascii_pct:.0f}%)"
                ),
                "recommended_tool": "de4dot",
            })

    return is_obfuscated, unique


def _detect_obfuscation_sync(target: str) -> Dict[str, Any]:
    """Synchronous obfuscation detection using dnfile metadata scanning."""
    if not DNFILE_AVAILABLE:
        return {"error": "dnfile is not installed. Install with: pip install dnfile"}

    try:
        dn = dnfile.dnPE(target)
    except Exception as e:
        return {"is_dotnet": False, "error": f"Not a valid .NET binary or parsing failed: {e}"}

    try:
        clr = getattr(dn, "net", None)
        if clr is None or not hasattr(clr, "struct") or clr.struct is None:
            return {"is_dotnet": False, "note": "File is not a .NET assembly."}

        # Gather custom attribute names
        custom_attrs: List[str] = []
        try:
            if hasattr(clr, "mdtables") and clr.mdtables:
                ca_table = clr.mdtables.CustomAttribute
                if ca_table and hasattr(ca_table, "rows"):
                    for row in ca_table.rows:
                        try:
                            # Try to get the attribute type name
                            if hasattr(row, "Type") and hasattr(row.Type, "row"):
                                type_row = row.Type.row
                                name = str(getattr(type_row, "Name", ""))
                                ns = str(getattr(type_row, "Namespace", ""))
                                full = f"{ns}.{name}" if ns else name
                                if full:
                                    custom_attrs.append(full)
                        except Exception:
                            continue
        except Exception:
            pass

        # Gather resource names
        resource_names: List[str] = []
        try:
            if hasattr(clr, "mdtables") and clr.mdtables:
                mr_table = clr.mdtables.ManifestResource
                if mr_table and hasattr(mr_table, "rows"):
                    for row in mr_table.rows:
                        name = str(getattr(row, "Name", ""))
                        if name:
                            resource_names.append(name)
        except Exception:
            pass

        # Gather type names for entropy analysis
        type_names: List[str] = []
        method_names: List[str] = []
        try:
            if hasattr(clr, "mdtables") and clr.mdtables:
                td_table = clr.mdtables.TypeDef
                if td_table and hasattr(td_table, "rows"):
                    for row in td_table.rows[:500]:  # Cap for perf
                        name = str(getattr(row, "TypeName", ""))
                        if name and name not in ("<Module>", "<PrivateImplementationDetails>"):
                            type_names.append(name)
                md_table = clr.mdtables.MethodDef
                if md_table and hasattr(md_table, "rows"):
                    for row in md_table.rows[:1000]:
                        name = str(getattr(row, "Name", ""))
                        if name:
                            method_names.append(name)
        except Exception:
            pass

        # Run detections
        attr_detections = _match_custom_attributes(custom_attrs, _OBFUSCATOR_SIGNATURES)
        resource_detections = _match_resource_patterns(resource_names, _OBFUSCATOR_SIGNATURES)
        all_detections = attr_detections + resource_detections

        # Calculate generic indicators
        all_names = type_names + method_names
        non_ascii_count = sum(1 for n in all_names if _is_non_ascii(n))
        non_ascii_pct = (non_ascii_count / len(all_names) * 100) if all_names else 0

        generic_indicators = {
            "type_name_entropy": round(_calc_name_entropy(type_names), 3),
            "method_name_entropy": round(_calc_name_entropy(method_names), 3),
            "non_ascii_name_pct": round(non_ascii_pct, 1),
            "total_types": len(type_names),
            "total_methods": len(method_names),
            "custom_attributes_scanned": len(custom_attrs),
            "resources_scanned": len(resource_names),
        }

        is_obfuscated, detections = _classify_obfuscator(all_detections, generic_indicators)

        return {
            "is_dotnet": True,
            "obfuscated": is_obfuscated,
            "detections": detections,
            "generic_indicators": generic_indicators,
            "file": os.path.basename(target),
        }
    finally:
        try:
            dn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
#  Subprocess helpers
# ---------------------------------------------------------------------------

def _build_de4dot_command(
    input_path: str,
    output_path: Optional[str] = None,
    detect_only: bool = False,
) -> List[str]:
    """Build the de4dot CLI command line (runs via mono on Linux).

    de4dot CLI syntax: de4dot [options] -f <file> [-o <output>]
    -d (detect and exit) must come before the -f flag.
    """
    args = ["mono", str(_DE4DOT_PATH)]
    if detect_only:
        args.append("-d")
    args.extend(["-f", input_path])
    if not detect_only and output_path:
        args.extend(["-o", output_path])
    return args


def _build_nrs_command(input_path: str, output_dir: str) -> List[str]:
    """Build the NETReactorSlayer CLI command line (self-contained binary)."""
    return [
        str(_NETREACTORSLAYER_PATH),
        input_path,
        "-o", output_dir,
    ]


def _build_ilspycmd_command(
    input_path: str,
    type_name: Optional[str] = None,
    output_dir: Optional[str] = None,
) -> List[str]:
    """Build the ilspycmd CLI command line."""
    cmd_path = str(_ILSPYCMD_PATH)
    # Check if it's on PATH instead
    if not Path(cmd_path).is_file():
        which = shutil.which("ilspycmd")
        if which:
            cmd_path = which
    args = [cmd_path, input_path]
    if type_name:
        args.extend(["-t", type_name])
    if output_dir:
        args.extend(["-o", output_dir, "-p"])
    return args


def _build_output_path(input_path: str, suffix: str = "_deobfuscated") -> str:
    """Derive output path from input path, placing in a temp directory."""
    base = os.path.basename(input_path)
    name, ext = os.path.splitext(base)
    return os.path.join(tempfile.gettempdir(), f"{name}{suffix}{ext or '.exe'}")


def _parse_de4dot_output(stdout: str) -> Dict[str, Any]:
    """Parse de4dot stdout for detected obfuscator info."""
    result: Dict[str, Any] = {"raw_output": stdout[:500]}
    # de4dot prints lines like: "Detected ConfuserEx v0.6.0 ..."
    for line in stdout.splitlines():
        lower = line.lower()
        if "detected" in lower:
            result["detected_obfuscator"] = line.strip()
        if "cleaned" in lower or "saved" in lower:
            result["status"] = "success"
    return result


async def _run_subprocess(
    args: List[str],
    timeout: int,
    label: str,
) -> Tuple[int, str, str]:
    """Run a subprocess with timeout, return (returncode, stdout, stderr)."""
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout + 30,
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except Exception:
            pass
        raise TimeoutError(f"{label} timed out after {timeout}s")

    stdout_str = stdout_bytes.decode("utf-8", errors="replace")
    stderr_str = stderr_bytes.decode("utf-8", errors="replace")
    return proc.returncode, stdout_str, stderr_str


# ---------------------------------------------------------------------------
#  Type name validation
# ---------------------------------------------------------------------------

_TYPE_NAME_RE = re.compile(r"^[a-zA-Z0-9._<>,\[\]` +]+$")


def _validate_type_name(type_name: str) -> str:
    """Validate and sanitize a .NET type name."""
    if len(type_name) > 500:
        raise ValueError("type_name too long (max 500 characters)")
    if not _TYPE_NAME_RE.match(type_name):
        raise ValueError(
            f"Invalid type_name: contains disallowed characters. "
            f"Allowed: letters, digits, dots, underscores, angle brackets, "
            f"commas, square brackets, backtick, space, plus."
        )
    return type_name


# ---------------------------------------------------------------------------
#  Tool 1: detect_dotnet_obfuscation
# ---------------------------------------------------------------------------

@tool_decorator
async def detect_dotnet_obfuscation(
    ctx: Context,
    file_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [Phase: triage] Detect .NET obfuscation by scanning metadata for known
    obfuscator signatures (custom attributes, resource patterns) and
    calculating name entropy indicators.

    Supports detection of: ConfuserEx, .NET Reactor, SmartAssembly,
    Dotfuscator, Babel .NET, Crypto Obfuscator, Agile.NET, Eazfuscator,
    Goliath.NET, Phoenix Protector, and generic obfuscation via entropy.

    When to use: As a first step before attempting dotnet_deobfuscate().
    Also useful for triage to determine if a .NET sample is obfuscated.

    Next steps: dotnet_deobfuscate() to remove obfuscation,
    dotnet_analyze() for metadata inspection, dotnet_decompile() for
    C# source recovery.

    Args:
        file_path: Optional path to a .NET binary. If None, uses the loaded file.
    """
    await ctx.info("Scanning .NET metadata for obfuscation signatures")
    target = _get_filepath(file_path)
    result = await asyncio.to_thread(_detect_obfuscation_sync, target)
    return await _check_mcp_response_size(ctx, result, "detect_dotnet_obfuscation")


# ---------------------------------------------------------------------------
#  Tool 2: dotnet_deobfuscate
# ---------------------------------------------------------------------------

@tool_decorator
async def dotnet_deobfuscate(
    ctx: Context,
    method: str = "auto",
    file_path: Optional[str] = None,
    output_path: Optional[str] = None,
    timeout_seconds: int = DOTNET_DEOBFUSCATE_TIMEOUT,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Deobfuscate a .NET binary using de4dot-cex or
    NETReactorSlayer. Outputs a cleaned binary registered as an artifact.

    Methods:
    - "auto": Detect obfuscator first, choose best tool automatically.
      If .NET Reactor detected → NETReactorSlayer first, else → de4dot first.
    - "de4dot": Use de4dot-cex (handles ~20 obfuscators including ConfuserEx).
    - "reactor_slayer": Use NETReactorSlayer (.NET Reactor specialist).
    - "detect_only": Only detect obfuscator (no file modification).

    When to use: After detect_dotnet_obfuscation() identifies obfuscation,
    or directly when you know the sample is obfuscated.

    Next steps: open_file() the deobfuscated output, dotnet_decompile()
    for C# source, dotnet_analyze() for metadata.

    Args:
        method: Deobfuscation method — "auto", "de4dot", "reactor_slayer", or "detect_only".
        file_path: Optional path. If None, uses the loaded file.
        output_path: Optional output path. If None, auto-derived from input.
        timeout_seconds: Subprocess timeout (1-600 seconds, default 120).
    """
    valid_methods = ("auto", "de4dot", "reactor_slayer", "detect_only")
    if method not in valid_methods:
        return {"error": f"Invalid method '{method}'. Must be one of: {', '.join(valid_methods)}"}

    timeout_seconds = max(1, min(timeout_seconds, 600))
    target = _get_filepath(file_path)

    if method == "detect_only":
        # Just run de4dot in detect-only mode
        if not _check_de4dot_available():
            return {"error": f"de4dot not available. {DE4DOT_IMPORT_ERROR}"}
        await ctx.info("Running de4dot detect-only mode")
        args = _build_de4dot_command(target, detect_only=True)
        try:
            rc, stdout, stderr = await _run_subprocess(args, timeout_seconds, "de4dot")
        except TimeoutError as e:
            return {"error": str(e)}
        result = _parse_de4dot_output(stdout)
        result["method"] = "detect_only"
        result["returncode"] = rc
        if stderr.strip():
            result["stderr"] = stderr[:300]
        return result

    # Determine output path
    out = output_path or _build_output_path(target)

    if method == "auto":
        await ctx.info("Auto-detecting obfuscator")
        detection = await asyncio.to_thread(_detect_obfuscation_sync, target)
        reactor_detected = False
        if detection.get("detections"):
            for det in detection["detections"]:
                if det.get("recommended_tool") == "reactor_slayer":
                    reactor_detected = True
                    break

        # Try best tool first, fallback to the other
        if reactor_detected and _check_netreactorslayer_available():
            result = await _try_nrs(ctx, target, out, timeout_seconds)
            if result.get("success"):
                result["detection"] = detection
                return result
            # Fallback to de4dot
            if _check_de4dot_available():
                await ctx.info("NRS failed/unchanged, trying de4dot")
                result = await _try_de4dot(ctx, target, out, timeout_seconds)
                result["detection"] = detection
                result["note"] = "NRS failed; fell back to de4dot"
                return result
        elif _check_de4dot_available():
            result = await _try_de4dot(ctx, target, out, timeout_seconds)
            if result.get("success"):
                result["detection"] = detection
                return result
            # Fallback to NRS
            if _check_netreactorslayer_available():
                await ctx.info("de4dot failed/unchanged, trying NRS")
                result = await _try_nrs(ctx, target, out, timeout_seconds)
                result["detection"] = detection
                result["note"] = "de4dot failed; fell back to NETReactorSlayer"
                return result

        if not _check_de4dot_available() and not _check_netreactorslayer_available():
            return {"error": f"No deobfuscation tools available. {DE4DOT_IMPORT_ERROR}"}
        result["detection"] = detection
        return result

    elif method == "de4dot":
        if not _check_de4dot_available():
            return {"error": f"de4dot not available. {DE4DOT_IMPORT_ERROR}"}
        return await _try_de4dot(ctx, target, out, timeout_seconds)

    elif method == "reactor_slayer":
        if not _check_netreactorslayer_available():
            return {"error": f"NETReactorSlayer not available. {NETREACTORSLAYER_IMPORT_ERROR}"}
        return await _try_nrs(ctx, target, out, timeout_seconds)

    return {"error": "Unexpected state"}


async def _try_de4dot(
    ctx: Context,
    target: str,
    output_path: str,
    timeout: int,
) -> Dict[str, Any]:
    """Attempt deobfuscation with de4dot-cex."""
    await ctx.info("Running de4dot-cex deobfuscation")
    args = _build_de4dot_command(target, output_path=output_path)
    try:
        rc, stdout, stderr = await _run_subprocess(args, timeout, "de4dot")
    except TimeoutError as e:
        return {"error": str(e), "method": "de4dot"}

    result: Dict[str, Any] = {
        "method": "de4dot",
        "returncode": rc,
    }
    result.update(_parse_de4dot_output(stdout))

    if rc == 0 and os.path.isfile(output_path):
        result["success"] = True
        result["output_path"] = output_path
        # Register as artifact
        try:
            with open(output_path, "rb") as f:
                data = f.read()
            artifact = _write_output_and_register_artifact(
                output_path, data, "dotnet_deobfuscate",
                f"de4dot deobfuscated: {os.path.basename(target)}",
            )
            result["artifact"] = artifact
        except Exception as e:
            result["artifact_error"] = str(e)[:200]
    else:
        result["success"] = False
        if stderr.strip():
            result["stderr"] = stderr[:500]

    return result


async def _try_nrs(
    ctx: Context,
    target: str,
    output_path: str,
    timeout: int,
) -> Dict[str, Any]:
    """Attempt deobfuscation with NETReactorSlayer."""
    await ctx.info("Running NETReactorSlayer deobfuscation")

    # NRS writes output in the input's directory. If the input is on a
    # read-only mount (e.g. Docker samples volume), copy to a temp dir.
    tmp_dir = tempfile.mkdtemp(prefix="nrs_")
    try:
        tmp_input = os.path.join(tmp_dir, os.path.basename(target))
        shutil.copy2(target, tmp_input)

        args = _build_nrs_command(tmp_input, tmp_dir)
        try:
            rc, stdout, stderr = await _run_subprocess(args, timeout, "NETReactorSlayer")
        except TimeoutError as e:
            return {"error": str(e), "method": "reactor_slayer"}

        result: Dict[str, Any] = {
            "method": "reactor_slayer",
            "returncode": rc,
            "raw_output": stdout[:500],
        }

        # NRS typically creates <name>_cleaned.<ext> in output dir
        nrs_output = None
        base, ext = os.path.splitext(os.path.basename(target))
        candidates = [
            os.path.join(tmp_dir, f"{base}_cleaned{ext}"),
            os.path.join(tmp_dir, f"{base}_Slayed{ext}"),
        ]
        for cand in candidates:
            if os.path.isfile(cand):
                nrs_output = cand
                break
        # Also scan for any new file that isn't the copy
        if nrs_output is None:
            for f in os.listdir(tmp_dir):
                fpath = os.path.join(tmp_dir, f)
                if fpath != tmp_input and os.path.isfile(fpath):
                    nrs_output = fpath
                    break

        if rc == 0 and nrs_output:
            # Move to final output path
            shutil.move(nrs_output, output_path)
            result["success"] = True
            result["output_path"] = output_path
            try:
                with open(output_path, "rb") as f:
                    data = f.read()
                artifact = _write_output_and_register_artifact(
                    output_path, data, "dotnet_deobfuscate",
                    f"NETReactorSlayer deobfuscated: {os.path.basename(target)}",
                )
                result["artifact"] = artifact
            except Exception as e:
                result["artifact_error"] = str(e)[:200]
        else:
            result["success"] = False
            if stderr.strip():
                result["stderr"] = stderr[:500]
    finally:
        # Clean up temp dir
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
#  Tool 3: dotnet_decompile
# ---------------------------------------------------------------------------

@tool_decorator
async def dotnet_decompile(
    ctx: Context,
    file_path: Optional[str] = None,
    type_name: Optional[str] = None,
    output_dir: Optional[str] = None,
    timeout_seconds: int = DOTNET_DECOMPILE_TIMEOUT,
    line_offset: int = 0,
    line_limit: int = 200,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Decompile a .NET assembly to C# source code using
    ilspycmd (ILSpy CLI). Returns paginated C# source or writes a full
    project to output_dir.

    Two modes:
    - stdout mode (no output_dir): Returns paginated C# source lines.
      Use type_name to decompile a specific class instead of the whole assembly.
    - project mode (with output_dir): Writes .csproj + .cs files to the directory.

    When to use: After dotnet_deobfuscate() to get readable C# source,
    or directly on unobfuscated .NET binaries.

    Next steps: add_note() to record findings, search_for_specific_strings()
    to find patterns in the decompiled code.

    Args:
        file_path: Optional path. If None, uses the loaded file.
        type_name: Optional fully-qualified type name to decompile (e.g. "MyNamespace.MyClass").
        output_dir: Optional directory for project output. If set, writes .csproj + .cs files.
        timeout_seconds: Subprocess timeout (1-600 seconds, default 120).
        line_offset: Start line for pagination (stdout mode only).
        line_limit: Max lines to return (stdout mode only, default 200).
    """
    if not _check_ilspycmd_available():
        return {"error": f"ilspycmd not available. {ILSPYCMD_IMPORT_ERROR}"}

    timeout_seconds = max(1, min(timeout_seconds, 600))
    line_limit = max(1, min(line_limit, MAX_TOOL_LIMIT))
    line_offset = max(0, line_offset)

    target = _get_filepath(file_path)

    if type_name:
        type_name = _validate_type_name(type_name)

    if output_dir:
        # Project mode — write .csproj + .cs files to directory
        await ctx.info("Decompiling .NET assembly to project")
        os.makedirs(output_dir, exist_ok=True)
        args = _build_ilspycmd_command(target, type_name=type_name, output_dir=output_dir)
        try:
            rc, stdout, stderr = await _run_subprocess(args, timeout_seconds, "ilspycmd")
        except TimeoutError as e:
            return {"error": str(e)}

        if rc != 0:
            return {
                "error": f"ilspycmd failed (exit code {rc})",
                "stderr": stderr[:500],
            }

        # List output files
        files: List[str] = []
        for root, _dirs, fnames in os.walk(output_dir):
            for fn in fnames:
                rel = os.path.relpath(os.path.join(root, fn), output_dir)
                files.append(rel)

        return {
            "mode": "project",
            "output_dir": output_dir,
            "files": files[:100],
            "file_count": len(files),
            "note": "Use Read tool to inspect individual .cs files" if files else "No output files generated",
        }
    else:
        # Stdout mode — return paginated C# source
        await ctx.info("Decompiling .NET assembly to C#")
        args = _build_ilspycmd_command(target, type_name=type_name)
        try:
            rc, stdout, stderr = await _run_subprocess(args, timeout_seconds, "ilspycmd")
        except TimeoutError as e:
            return {"error": str(e)}

        if rc != 0:
            return {
                "error": f"ilspycmd failed (exit code {rc})",
                "stderr": stderr[:500],
            }

        lines = stdout.splitlines()
        total = len(lines)

        # Cap total lines
        if total > DOTNET_DECOMPILE_MAX_OUTPUT_LINES:
            lines = lines[:DOTNET_DECOMPILE_MAX_OUTPUT_LINES]
            total = len(lines)

        # Paginate
        page = lines[line_offset:line_offset + line_limit]
        returned = len(page)

        result: Dict[str, Any] = {
            "mode": "stdout",
            "lines": page,
            "file": os.path.basename(target),
            "_pagination": {
                "total": total,
                "offset": line_offset,
                "limit": line_limit,
                "returned": returned,
                "has_more": (line_offset + returned) < total,
            },
        }
        if type_name:
            result["type_name"] = type_name

        return await _check_mcp_response_size(
            ctx, result, "dotnet_decompile",
            "line_offset and line_limit parameters",
        )
