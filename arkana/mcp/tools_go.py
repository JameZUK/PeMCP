"""MCP tools for Go binary analysis with GoReSym/pygore/string-scan fallback."""
import asyncio
import json
import os
import re
from typing import Dict, Any, Optional
from arkana.config import (
    state, logger, Context,
    PYGORE_AVAILABLE, GORESYM_AVAILABLE, _GORESYM_PATH,
)
from arkana.mcp.server import tool_decorator, _check_mcp_response_size
from arkana.mcp._format_helpers import _get_filepath
from arkana.constants import MAX_TOOL_LIMIT

if PYGORE_AVAILABLE:
    import pygore

# GoReSym subprocess timeout (seconds)
_GORESYM_TIMEOUT = 120


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


def _run_pygore(filepath: str, limit: int, func_cap: int, method_cap: int) -> Dict[str, Any]:
    """Run pygore analysis synchronously (called via asyncio.to_thread).

    Returns parsed result dict with ``analysis_method: "pygore"``.
    """
    f = pygore.GoFile(filepath)
    try:
        result: Dict[str, Any] = {
            "analysis_method": "pygore",
        }

        # Compiler version
        compiler_version = None
        try:
            cv = f.get_compiler_version()
            compiler_version = _safe_str(cv)
        except Exception:
            pass
        result["go_version"] = compiler_version

        # Build ID
        build_id = None
        try:
            if hasattr(f, 'get_build_id'):
                bid = f.get_build_id()
                build_id = _safe_str(bid)
        except Exception:
            pass
        result["build_id"] = build_id

        # Packages
        packages = []
        total_pkg_count = 0
        try:
            for pkg in f.get_packages():
                total_pkg_count += 1
                if len(packages) >= limit:
                    continue  # keep counting total

                funcs = []
                for fn in (pkg.functions or []):
                    funcs.append({
                        "name": _safe_str(fn.name if hasattr(fn, 'name') else fn),
                        "offset": _safe_int(fn.offset if hasattr(fn, 'offset') else None),
                        "end": _safe_int(fn.end if hasattr(fn, 'end') else None),
                    })

                methods = []
                for m in (pkg.methods or []):
                    methods.append({
                        "receiver": _safe_str(m.receiver if hasattr(m, 'receiver') else None),
                        "name": _safe_str(m.name if hasattr(m, 'name') else m),
                        "offset": _safe_int(m.offset if hasattr(m, 'offset') else None),
                    })

                packages.append({
                    "name": _safe_str(pkg.name if hasattr(pkg, 'name') else pkg),
                    "function_count": len(funcs),
                    "method_count": len(methods),
                    "functions": funcs[:func_cap],
                    "methods": methods[:method_cap],
                })
        except Exception as e:
            result["packages_error"] = str(e)[:200]
        result["packages"] = packages

        # Vendor packages (third-party dependencies)
        vendor_pkgs = []
        total_vendor_count = 0
        vendor_func_cap = max(2, func_cap // 2)
        try:
            for pkg in f.get_vendor_packages():
                total_vendor_count += 1
                if len(vendor_pkgs) >= limit:
                    continue

                vendor_funcs = []
                for fn in (pkg.functions or []):
                    vendor_funcs.append({
                        "name": _safe_str(fn.name if hasattr(fn, 'name') else fn),
                        "offset": _safe_int(fn.offset if hasattr(fn, 'offset') else None),
                    })
                vendor_pkgs.append({
                    "name": _safe_str(pkg.name if hasattr(pkg, 'name') else pkg),
                    "function_count": len(vendor_funcs),
                    "functions": vendor_funcs[:vendor_func_cap],
                })
        except Exception:
            pass
        result["vendor_packages"] = vendor_pkgs

        # Types
        types = []
        total_type_count = 0
        try:
            for t in f.get_types():
                total_type_count += 1
                if len(types) >= limit:
                    continue
                types.append({
                    "name": _safe_str(t.name if hasattr(t, 'name') else t),
                    "kind": _safe_str(t.kind if hasattr(t, 'kind') else None),
                })
        except Exception:
            pass
        result["types"] = types

        result["summary"] = {
            "packages_returned": len(packages),
            "packages_total": total_pkg_count,
            "vendor_packages_returned": len(vendor_pkgs),
            "vendor_packages_total": total_vendor_count,
            "types_returned": len(types),
            "types_total": total_type_count,
            "limit_applied": limit,
            "funcs_per_package_cap": func_cap,
        }

        # Validate: a real Go binary should have at least one of: compiler
        # version, packages, or types.
        has_go_artifacts = bool(
            compiler_version
            or packages
            or vendor_pkgs
            or types
        )
        result["is_go_binary"] = has_go_artifacts

        return result
    finally:
        if hasattr(f, 'close'):
            f.close()


@tool_decorator
async def go_analyze(
    ctx: Context,
    file_path: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: triage] Analyses a Go binary: compiler version, packages, function
    names with addresses, type definitions. Works on stripped binaries via pclntab.

    When to use: When detect_binary_format() identifies a Go binary. Go binaries
    have unique structure — this tool extracts Go-specific metadata.

    Uses GoReSym (preferred), pygore, or string-scan fallback to extract
    Go compiler version, module path, packages, functions, types, and
    build information from Go binaries.

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

    # ── Fallback chain: GoReSym → pygore → string scan ──
    result = None
    fallback_reasons = []

    # 1. Try GoReSym first (most modern, handles recent Go versions well)
    if GORESYM_AVAILABLE:
        try:
            result = await _run_goresym(target)
        except Exception as e:
            fallback_reasons.append(f"GoReSym failed: {str(e)[:200]}")
            logger.debug("go_analyze: GoReSym failed, trying next method: %s", e)

    # 2. Try pygore second
    if result is None and PYGORE_AVAILABLE:
        try:
            result = await asyncio.to_thread(
                _run_pygore, target, limit, func_cap, method_cap,
            )
            # pygore parsed but found nothing useful — not a Go binary by its view
            if result and not result.get("is_go_binary"):
                # Don't treat as final — let string scan try
                fallback_reasons.append("pygore found no Go metadata")
                result = None
        except Exception as e:
            fallback_reasons.append(f"pygore failed: {str(e)[:200]}")
            logger.debug("go_analyze: pygore failed, trying string scan: %s", e)

    # 3. Final fallback: string scan
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

    # Add file basename
    result["file"] = os.path.basename(target)

    return await _check_mcp_response_size(ctx, result, "go_analyze", "the 'limit' parameter")
