"""MCP tools for Go binary analysis with GoReSym/pygore/gopclntab/string-scan fallback."""
import asyncio
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
from arkana.config import (
    state, logger, Context,
    PYGORE_AVAILABLE, GORESYM_AVAILABLE, _GORESYM_PATH,
)
from arkana.mcp.server import tool_decorator, _check_mcp_response_size
from arkana.mcp._format_helpers import _get_filepath
from arkana.constants import MAX_TOOL_LIMIT
from arkana.parsers.go_pclntab import (
    parse_gopclntab,
    _parse_elf_section_headers,
    _parse_macho_section_headers,
)
from arkana.parsers.go_types import parse_go_types

# GoReSym subprocess timeout (seconds)
_GORESYM_TIMEOUT = 120

# pygore subprocess runner — isolates the CGO Go runtime from the main
# process so a Go GC crash (lfstack.push on ARM64) doesn't kill Arkana.
_PYGORE_RUNNER = Path(__file__).resolve().parent.parent.parent / "scripts" / "pygore_runner.py"
_PYGORE_TIMEOUT = 120  # seconds


def _go_string_scan(filepath: str, scan_limit: int = 2 * 1024 * 1024) -> Dict[str, Any]:
    """Fallback Go detection by scanning binary for Go-specific strings.

    Works when pygore cannot parse the binary (e.g. newer Go versions).
    Returns a dict with detection results and any extracted info.
    """
    markers_found = []
    go_version = None

    with open(filepath, 'rb') as f:
        data = f.read(scan_limit)

    marker_checks = [
        (b'runtime.main', "runtime.main (Go runtime entry)"),
        (b'runtime.goexit', "runtime.goexit"),
        (b'runtime/internal/', "runtime/internal/ (Go runtime internals)"),
        (b'go.buildid', "go.buildid"),
        (b'Go build', "Go build marker"),
        (b'go.itab.', "go.itab (interface tables)"),
        (b'go.string.', "go.string (string pool)"),
        (b'runtime.gcBgMarkWorker', "runtime.gcBgMarkWorker (GC)"),
        (b'runtime.newproc', "runtime.newproc (goroutine spawn)"),
        (b'runtime.mstart', "runtime.mstart (M scheduler)"),
        (b'sync.(*Mutex)', "sync.Mutex"),
        (b'fmt.Sprintf', "fmt.Sprintf"),
        (b'net/http', "net/http"),
    ]

    for marker_bytes, description in marker_checks:
        if marker_bytes in data:
            markers_found.append(description)

    # Try to extract Go version string (e.g. "go1.21.5" or "Go cmd/compile go1.22")
    version_patterns = [
        rb'go(1\.\d+(?:\.\d+)?)',
        rb'Go cmd/compile go(1\.\d+(?:\.\d+)?)',
    ]
    for pat in version_patterns:
        match = re.search(pat, data)
        if match:
            try:
                go_version = "go" + match.group(1).decode('utf-8', 'ignore').strip()[:20]
            except Exception:
                pass
            break

    is_go = len(markers_found) >= 2 or go_version is not None

    return {
        "is_go_binary": is_go,
        "analysis_method": "string_scan",
        "markers_found": markers_found,
        "marker_count": len(markers_found),
        "go_version": go_version,
    }


def _run_gopclntab(filepath: str, limit: int, func_cap: int) -> Optional[Dict[str, Any]]:
    """Parse gopclntab from a Go binary file.

    Returns a dict in go_analyze format, or None if not a Go binary.
    """
    with open(filepath, "rb") as f:
        file_data = f.read()

    # Build sections list from the binary format
    sections: List[Dict[str, Any]] = []
    text_vaddr = 0

    # Try PE sections first (if a PE is loaded)
    try:
        pe_obj = state.pe_object
        if pe_obj is not None and hasattr(pe_obj, "sections"):
            for sec in pe_obj.sections:
                try:
                    name = sec.Name.decode("utf-8", errors="replace").rstrip("\x00")
                    sections.append({
                        "name": name,
                        "offset": sec.PointerToRawData,
                        "size": sec.SizeOfRawData,
                        "vaddr": sec.VirtualAddress + (pe_obj.OPTIONAL_HEADER.ImageBase if hasattr(pe_obj, "OPTIONAL_HEADER") else 0),
                    })
                    if name.lower() == ".text":
                        text_vaddr = sections[-1]["vaddr"]
                except Exception:
                    continue
    except Exception:
        pass

    # Try ELF/Mach-O section headers if no PE sections found
    if not sections:
        sections = _parse_elf_section_headers(file_data)
        if not sections:
            sections = _parse_macho_section_headers(file_data)
        # Find .text vaddr
        for sec in sections:
            name_lower = sec.get("name", "").lower()
            if name_lower in (".text", "__text"):
                text_vaddr = sec.get("vaddr", 0)
                break

    parsed = parse_gopclntab(file_data, sections, text_vaddr)
    if parsed is None:
        return None

    functions = parsed.get("functions", [])
    if not functions:
        return None

    # Group functions by package (Go convention: package.Function)
    packages: Dict[str, List[Dict[str, Any]]] = {}
    for func in functions:
        name = func.get("name", "")
        pkg = _extract_go_package(name)
        if pkg not in packages:
            packages[pkg] = []
        packages[pkg].append({
            "name": name,
            "address": hex(func["address"]) if isinstance(func.get("address"), int) else str(func.get("address", "")),
        })

    # Sort packages, apply limits
    pkg_list = []
    sorted_pkgs = sorted(packages.keys())
    for pkg_name in sorted_pkgs[:limit]:
        funcs = packages[pkg_name][:func_cap]
        pkg_list.append({
            "name": pkg_name,
            "functions": funcs,
            "function_count": len(packages[pkg_name]),
        })

    result: Dict[str, Any] = {
        "is_go_binary": True,
        "analysis_method": "gopclntab",
        "go_version": parsed.get("go_version_hint", ""),
        "function_count": parsed["function_count"],
        "packages": pkg_list,
        "package_count": len(packages),
    }

    source_files = parsed.get("source_files", [])
    if source_files:
        result["source_files"] = source_files[:200]
        result["source_file_count"] = len(source_files)

    # Parse Go type descriptors (typelink/itab sections)
    try:
        go_ver = parsed.get("go_version_hint", "")
        ptr_sz = parsed.get("pointer_size", 8)
        type_result = parse_go_types(
            file_data, sections,
            go_version_hint=go_ver,
            ptr_size=ptr_sz,
        )
        if type_result:
            if type_result.get("structs"):
                result["structs"] = type_result["structs"][:limit]
                result["struct_count"] = type_result.get("struct_count", 0)
            if type_result.get("interfaces"):
                result["interfaces"] = type_result["interfaces"][:limit]
                result["interface_count"] = type_result.get("interface_count", 0)
            if type_result.get("types"):
                result["types"] = type_result["types"][:limit]
            if type_result.get("itabs"):
                result["itabs"] = type_result["itabs"][:limit]
                result["itab_count"] = type_result.get("itab_count", 0)
            if type_result.get("type_packages"):
                result["type_packages"] = type_result["type_packages"]
            result["type_count"] = type_result.get("type_count", 0)
    except Exception as e:
        logger.debug("go_analyze: type parsing failed: %s", e)
        parse_errors = result.get("parse_errors", [])
        parse_errors.append(f"type parsing: {str(e)[:200]}")
        result["parse_errors"] = parse_errors

    parse_errors = parsed.get("parse_errors", [])
    if parse_errors and "parse_errors" not in result:
        result["parse_errors"] = parse_errors[:20]
    elif parse_errors:
        existing = result.get("parse_errors", [])
        for err in parse_errors[:20]:
            if err not in existing:
                existing.append(err)
        result["parse_errors"] = existing[:20]

    return result


def _extract_go_package(func_name: str) -> str:
    """Extract package name from a Go function name.

    Go naming: ``package.Function``, ``package.(*Type).Method``,
    ``crypto/tls.(*Conn).Read``.
    """
    if not func_name:
        return "unknown"

    # Remove method receiver: find first '(' and work with prefix
    paren = func_name.find("(")
    prefix = func_name[:paren] if paren > 0 else func_name

    # Package is everything before the last '.'
    dot = prefix.rfind(".")
    if dot > 0:
        return prefix[:dot]

    return "unknown"


def _safe_str(val, fallback=""):
    """Convert any value to a JSON-safe string."""
    if val is None:
        return None
    try:
        return str(val)
    except Exception:
        return fallback


def _safe_int(val):
    """Convert any value to a JSON-safe int, or None."""
    if val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        try:
            return int(str(val), 0)
        except Exception:
            return None


async def _run_goresym(filepath: str) -> Dict[str, Any]:
    """Run GoReSym binary and parse JSON output.

    GoReSym flags: -t (types), -d (type definitions), -p (file paths).
    Returns parsed result dict with ``analysis_method: "goresym"``.

    Raises RuntimeError on non-zero exit or invalid JSON.
    """
    proc = await asyncio.create_subprocess_exec(
        _GORESYM_PATH, "-t", "-d", "-p", filepath,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=_GORESYM_TIMEOUT,
        )
    except asyncio.TimeoutError:
        # Kill the process on timeout and reap to avoid zombie
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        raise RuntimeError(
            f"GoReSym timed out after {_GORESYM_TIMEOUT}s"
        )

    if proc.returncode != 0:
        raise RuntimeError(
            f"GoReSym exited with code {proc.returncode}: "
            f"{stderr.decode('utf-8', errors='replace')[:500]}"
        )

    raw = stdout.decode("utf-8", errors="replace")
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(
            f"GoReSym returned invalid JSON: {exc} "
            f"(first 200 chars: {raw[:200]})"
        )

    # ---- Parse GoReSym JSON output into Arkana format ----
    result: Dict[str, Any] = {
        "go_version": data.get("Version", ""),
        "build_id": data.get("BuildId", ""),
        "module_info": {},
        "packages": [],
        "types": [],
        "interfaces": [],
        "source_files": [],
        "analysis_method": "goresym",
    }

    # Parse module / build info
    build_info = data.get("BuildInfo")
    if build_info and isinstance(build_info, dict):
        main_mod = build_info.get("Main") or {}
        deps_raw = build_info.get("Deps") or []
        result["module_info"] = {
            "path": build_info.get("Path", ""),
            "main_module": main_mod.get("Path", "") if isinstance(main_mod, dict) else "",
            "go_version": build_info.get("GoVersion", ""),
            "deps": [
                {"path": d.get("Path", ""), "version": d.get("Version", "")}
                for d in deps_raw
                if isinstance(d, dict)
            ],
        }

    # Parse user functions — group by package
    packages_seen: Dict[str, Dict[str, Any]] = {}  # name → package dict
    user_funcs = data.get("UserFunctions") or []
    for func in user_funcs:
        if not isinstance(func, dict):
            continue
        pkg_name = func.get("PackageName", "unknown") or "unknown"
        if pkg_name not in packages_seen:
            packages_seen[pkg_name] = {
                "name": pkg_name,
                "functions": [],
            }
        packages_seen[pkg_name]["functions"].append({
            "name": func.get("FullName", func.get("Name", "")),
            "address": hex(func.get("Start", 0)) if func.get("Start") else "",
            "end": hex(func.get("End", 0)) if func.get("End") else "",
        })
    result["packages"] = list(packages_seen.values())
    parsed_func_count = sum(len(p["functions"]) for p in result["packages"])

    # Parse standard library functions (count only — too many to list)
    std_funcs = data.get("StdFunctions") or []
    result["std_function_count"] = len(std_funcs)

    # Parse types (cap at 200 to prevent huge responses)
    for t in (data.get("Types") or [])[:200]:
        if not isinstance(t, dict):
            continue
        result["types"].append({
            "name": t.get("Str", ""),
            "kind": t.get("Kind", ""),
            "size": t.get("Size", 0),
        })

    # Parse interfaces (cap at 100)
    for iface in (data.get("Interfaces") or [])[:100]:
        if not isinstance(iface, dict):
            continue
        methods_raw = iface.get("Methods") or []
        result["interfaces"].append({
            "name": iface.get("Str", ""),
            "methods": [
                m.get("Name", "") for m in methods_raw
                if isinstance(m, dict)
            ][:20],
        })

    # Collect unique source files from user functions (cap at 200)
    source_files: set = set()
    for func in user_funcs:
        if isinstance(func, dict) and func.get("SourceFile"):
            source_files.add(func["SourceFile"])
    result["source_files"] = sorted(source_files)[:200]

    result["function_count"] = parsed_func_count
    result["type_count"] = len(data.get("Types") or [])

    return result


async def _run_pygore(filepath: str, limit: int, func_cap: int, method_cap: int) -> Dict[str, Any]:
    """Run pygore in an isolated subprocess.

    pygore wraps libgore (CGO, Go 1.16 runtime).  On ARM64 the Go 1.16
    GC has a known ``lfstack.push`` bug that can SIGABRT the process when
    heap addresses are high.  Running in a subprocess means only the child
    dies — the parent falls through to the pure-Python gopclntab parser.

    Returns parsed result dict with ``analysis_method: "pygore"``.
    Raises RuntimeError on subprocess failure.
    """
    cmd = json.dumps({
        "filepath": filepath,
        "limit": limit,
        "func_cap": func_cap,
        "method_cap": method_cap,
    })
    proc = await asyncio.create_subprocess_exec(
        sys.executable, str(_PYGORE_RUNNER),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=cmd.encode()),
            timeout=_PYGORE_TIMEOUT,
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        raise RuntimeError(f"pygore timed out after {_PYGORE_TIMEOUT}s")

    if proc.returncode != 0:
        # Non-zero exit — could be SIGABRT from Go runtime crash
        stderr_text = stderr.decode("utf-8", errors="replace")[:500] if stderr else ""
        # Try to parse stdout anyway — runner writes JSON even on some errors
        if stdout:
            try:
                data = json.loads(stdout.decode("utf-8", errors="replace"))
                if "error" in data:
                    raise RuntimeError(f"pygore error: {data['error']}")
            except (json.JSONDecodeError, ValueError):
                pass
        signal_num = -proc.returncode if proc.returncode < 0 else proc.returncode
        raise RuntimeError(
            f"pygore subprocess crashed (exit={signal_num}): {stderr_text}"
        )

    raw = stdout.decode("utf-8", errors="replace")
    try:
        result = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(
            f"pygore returned invalid JSON: {exc} (first 200 chars: {raw[:200]})"
        )

    if "error" in result:
        raise RuntimeError(f"pygore error: {result['error']}")

    return result


@tool_decorator
async def go_analyze(
    ctx: Context,
    file_path: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: triage] Analyses a Go binary: compiler version, packages, function
    names with addresses, type definitions. Works on stripped binaries via pclntab.

    ---compact: analyze Go binary — version, packages, functions via GoReSym/pclntab | needs: file

    When to use: When detect_binary_format() identifies a Go binary. Go binaries
    have unique structure — this tool extracts Go-specific metadata.

    Uses GoReSym (preferred), pygore, gopclntab parser, or string-scan
    fallback to extract Go compiler version, module path, packages,
    functions, types, and build information from Go binaries.

    Next steps: decompile_function_with_angr() on main/init functions,
    get_triage_report() for risk assessment.

    Args:
        file_path: Optional path to a Go binary. If None, uses the loaded file.
        limit: Max packages/vendor_packages/types to return (default 20).
    """
    await ctx.info("Analysing Go binary")
    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    target = _get_filepath(file_path)

    # Scale per-package detail caps inversely with package limit to
    # keep total response size bounded (~60KB target).
    func_cap = max(3, min(20, 100 // max(1, limit)))
    method_cap = func_cap

    # ── Fallback chain: GoReSym → pygore → gopclntab → string scan ──
    result = None
    fallback_reasons = []

    # 1. Try GoReSym first (most modern, handles recent Go versions well)
    if GORESYM_AVAILABLE:
        try:
            result = await _run_goresym(target)
        except Exception as e:
            fallback_reasons.append(f"GoReSym failed: {str(e)[:200]}")
            logger.debug("go_analyze: GoReSym failed, trying next method: %s", e)

    # 2. Try pygore second (runs in isolated subprocess to survive Go GC crashes)
    if result is None and PYGORE_AVAILABLE and _PYGORE_RUNNER.exists():
        try:
            result = await _run_pygore(target, limit, func_cap, method_cap)
            # pygore parsed but found nothing useful — not a Go binary by its view
            if result and not result.get("is_go_binary"):
                # Don't treat as final — let string scan try
                fallback_reasons.append("pygore found no Go metadata")
                result = None
        except Exception as e:
            fallback_reasons.append(f"pygore failed: {str(e)[:200]}")
            logger.debug("go_analyze: pygore failed, trying string scan: %s", e)

    # 3. Try gopclntab parser (pure-Python, no external deps)
    if result is None:
        try:
            result = await asyncio.to_thread(_run_gopclntab, target, limit, func_cap)
            if result and not result.get("function_count"):
                fallback_reasons.append("gopclntab: no functions found")
                result = None
        except Exception as e:
            fallback_reasons.append(f"gopclntab: {str(e)[:200]}")
            logger.debug("go_analyze: gopclntab failed: %s", e)

    # 4. Final fallback: string scan
    if result is None:
        result = await asyncio.to_thread(_go_string_scan, target)
        if not result.get("is_go_binary"):
            # None of the methods detected Go — return error
            if not GORESYM_AVAILABLE and not PYGORE_AVAILABLE:
                result["note"] = (
                    "Neither GoReSym nor pygore is available. "
                    "Install GoReSym for best results, or pygore (pip install pygore). "
                    "String scan did not detect Go markers."
                )
            else:
                result["note"] = "Not a Go binary or no Go metadata could be extracted."
        elif fallback_reasons:
            result["note"] = (
                "Detected as Go via string patterns. "
                "Use elf_analyze() for symbol and dependency information."
            )

    # Attach fallback chain info when we fell back
    if fallback_reasons:
        result["fallback_reasons"] = fallback_reasons

    # Cache Go version on state for downstream tools (e.g. ABI annotations)
    go_ver = result.get("go_version") or result.get("compiler_version") or ""
    if go_ver:
        state._cached_go_version = str(go_ver)

    # Add file basename
    result["file"] = os.path.basename(target)

    return await _check_mcp_response_size(ctx, result, "go_analyze", "the 'limit' parameter")
