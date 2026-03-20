"""MCP tools for Go binary analysis using pygore."""
import asyncio
import os
import re
from typing import Dict, Any, Optional
from arkana.config import state, logger, Context, PYGORE_AVAILABLE
from arkana.mcp.server import tool_decorator, _check_mcp_response_size
from arkana.mcp._format_helpers import _check_lib, _get_filepath
from arkana.constants import MAX_TOOL_LIMIT

if PYGORE_AVAILABLE:
    import pygore


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
        "detection_method": "string_scan" if is_go else None,
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

    Next steps: decompile_function_with_angr() on main/init functions,
    get_triage_report() for risk assessment.

    Args:
        file_path: Optional path to a Go binary. If None, uses the loaded file.
        limit: Max packages/vendor_packages/types to return (default 20).
    """
    await ctx.info("Analysing Go binary")
    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    _check_lib("pygore", PYGORE_AVAILABLE, "go_analyze")
    target = _get_filepath(file_path)

    def _parse():
        try:
            f = pygore.GoFile(target)
        except Exception as e:
            # Fallback: string-based detection for binaries pygore can't parse
            try:
                scan_result = _go_string_scan(target)
                if scan_result["is_go_binary"]:
                    return {
                        "file": os.path.basename(target),
                        **scan_result,
                        "note": (
                            "Detected as Go via string patterns (pygore parsing failed). "
                            "Use elf_analyze() for symbol and dependency information."
                        ),
                        "pygore_error": str(e)[:200],
                    }
            except Exception:
                pass
            return {"error": f"Not a Go binary or pygore parsing failed: {e}"}

        try:
            result: Dict[str, Any] = {"file": os.path.basename(target)}

            # Scale per-package detail caps inversely with package limit to
            # keep total response size bounded (~60KB target).
            # With limit=20: 5 funcs, 5 methods per package = 200 items
            # With limit=5:  15 funcs, 15 methods per package = 150 items
            # With limit=1:  20 funcs, 20 methods per package = 40 items
            func_cap = max(3, min(20, 100 // max(1, limit)))
            method_cap = func_cap

            # Compiler version
            compiler_version = None
            try:
                cv = f.get_compiler_version()
                compiler_version = _safe_str(cv)
            except Exception:
                pass
            result["compiler_version"] = compiler_version

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

            if not has_go_artifacts:
                return {
                    "error": "Not a Go binary or pygore could not find Go metadata.",
                    "is_go_binary": False,
                    "file": os.path.basename(target),
                }

            return result
        finally:
            if hasattr(f, 'close'):
                f.close()

    result = await asyncio.to_thread(_parse)
    return await _check_mcp_response_size(ctx, result, "go_analyze", "the 'limit' parameter")
