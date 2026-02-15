"""MCP tools for Go binary analysis using pygore."""
import asyncio
from typing import Dict, Any, Optional
from pemcp.config import state, logger, Context, PYGORE_AVAILABLE
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size
from pemcp.mcp._format_helpers import _check_lib, _get_filepath

if PYGORE_AVAILABLE:
    import pygore


@tool_decorator
async def go_analyze(
    ctx: Context,
    file_path: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Analyses a Go binary: compiler version, packages, function names with addresses,
    type definitions. Works on stripped binaries by parsing pclntab.

    Args:
        file_path: Optional path to a Go binary. If None, uses the loaded file.
        limit: Max entries per category.
    """
    await ctx.info("Analysing Go binary")
    _check_lib("pygore", PYGORE_AVAILABLE, "go_analyze")
    target = _get_filepath(file_path)

    def _parse():
        try:
            f = pygore.GoFile(target)
        except Exception as e:
            return {"error": f"Not a Go binary or pygore parsing failed: {e}"}

        result: Dict[str, Any] = {"file": target}

        # Compiler version
        compiler_version = None
        try:
            compiler_version = f.get_compiler_version()
        except Exception:
            pass
        result["compiler_version"] = compiler_version

        # Build ID
        build_id = None
        try:
            build_id = f.get_build_id() if hasattr(f, 'get_build_id') else None
        except Exception:
            pass
        result["build_id"] = build_id

        # Packages
        packages = []
        try:
            for pkg in f.get_packages():
                funcs = []
                for fn in (pkg.functions or []):
                    funcs.append({
                        "name": fn.name if hasattr(fn, 'name') else str(fn),
                        "offset": fn.offset if hasattr(fn, 'offset') else None,
                        "end": fn.end if hasattr(fn, 'end') else None,
                    })

                methods = []
                for m in (pkg.methods or []):
                    methods.append({
                        "receiver": m.receiver if hasattr(m, 'receiver') else None,
                        "name": m.name if hasattr(m, 'name') else str(m),
                        "offset": m.offset if hasattr(m, 'offset') else None,
                    })

                packages.append({
                    "name": pkg.name if hasattr(pkg, 'name') else str(pkg),
                    "function_count": len(funcs),
                    "method_count": len(methods),
                    "functions": funcs[:20],
                    "methods": methods[:20],
                })
                if len(packages) >= limit:
                    break
        except Exception as e:
            result["packages_error"] = str(e)
        result["packages"] = packages

        # Vendor packages (third-party dependencies)
        vendor_pkgs = []
        try:
            for pkg in f.get_vendor_packages():
                vendor_funcs = []
                for fn in (pkg.functions or []):
                    vendor_funcs.append({
                        "name": fn.name if hasattr(fn, 'name') else str(fn),
                        "offset": fn.offset if hasattr(fn, 'offset') else None,
                    })
                vendor_pkgs.append({
                    "name": pkg.name if hasattr(pkg, 'name') else str(pkg),
                    "function_count": len(vendor_funcs),
                    "functions": vendor_funcs[:10],
                })
                if len(vendor_pkgs) >= limit:
                    break
        except Exception:
            pass
        result["vendor_packages"] = vendor_pkgs

        # Types
        types = []
        try:
            for t in f.get_types():
                types.append({
                    "name": t.name if hasattr(t, 'name') else str(t),
                    "kind": t.kind if hasattr(t, 'kind') else None,
                })
                if len(types) >= limit:
                    break
        except Exception:
            pass
        result["types"] = types

        result["summary"] = {
            "packages": len(packages),
            "vendor_packages": len(vendor_pkgs),
            "types": len(types),
        }

        f.close() if hasattr(f, 'close') else None

        # Validate: a real Go binary should have at least one of: compiler
        # version, packages, or types.  If pygore returned nothing
        # meaningful, this is not actually a Go binary.
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
                "file": target,
            }

        return result

    result = await asyncio.to_thread(_parse)
    return await _check_mcp_response_size(ctx, result, "go_analyze", "the 'limit' parameter")
