#!/usr/bin/env python
"""Standalone pygore runner -- invoked via subprocess from Arkana.

Reads a JSON command from stdin, runs pygore analysis, and writes a JSON
result to stdout.

pygore wraps libgore (a CGO shared library compiled with Go 1.16).  On
ARM64 the Go 1.16 GC has a known ``lfstack.push`` bug that can SIGABRT
the entire process when heap addresses are high.  Running pygore in a
subprocess isolates that crash so only the child dies -- the parent
Arkana process falls through to the pure-Python gopclntab parser.
"""
import json
import sys


def _safe_str(val, fallback=None):
    if val is None:
        return fallback
    try:
        return str(val)
    except Exception:
        return fallback


def _safe_int(val):
    if val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        try:
            return int(str(val), 0)
        except Exception:
            return None


def run_pygore(filepath: str, limit: int, func_cap: int, method_cap: int) -> dict:
    """Run pygore analysis and return a result dict."""
    import pygore  # imported here so crash stays in this process

    f = pygore.GoFile(filepath)
    try:
        result = {
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
            if hasattr(f, "get_build_id"):
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
                    continue

                funcs = []
                for fn in pkg.functions or []:
                    funcs.append({
                        "name": _safe_str(fn.name if hasattr(fn, "name") else fn),
                        "offset": _safe_int(fn.offset if hasattr(fn, "offset") else None),
                        "end": _safe_int(fn.end if hasattr(fn, "end") else None),
                    })

                methods = []
                for m in pkg.methods or []:
                    methods.append({
                        "receiver": _safe_str(m.receiver if hasattr(m, "receiver") else None),
                        "name": _safe_str(m.name if hasattr(m, "name") else m),
                        "offset": _safe_int(m.offset if hasattr(m, "offset") else None),
                    })

                packages.append({
                    "name": _safe_str(pkg.name if hasattr(pkg, "name") else pkg),
                    "function_count": len(funcs),
                    "method_count": len(methods),
                    "functions": funcs[:func_cap],
                    "methods": methods[:method_cap],
                })
        except Exception as e:
            result["packages_error"] = str(e)[:200]
        result["packages"] = packages

        # Vendor packages
        vendor_pkgs = []
        total_vendor_count = 0
        vendor_func_cap = max(2, func_cap // 2)
        try:
            for pkg in f.get_vendor_packages():
                total_vendor_count += 1
                if len(vendor_pkgs) >= limit:
                    continue

                vendor_funcs = []
                for fn in pkg.functions or []:
                    vendor_funcs.append({
                        "name": _safe_str(fn.name if hasattr(fn, "name") else fn),
                        "offset": _safe_int(fn.offset if hasattr(fn, "offset") else None),
                    })
                vendor_pkgs.append({
                    "name": _safe_str(pkg.name if hasattr(pkg, "name") else pkg),
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
                    "name": _safe_str(t.name if hasattr(t, "name") else t),
                    "kind": _safe_str(t.kind if hasattr(t, "kind") else None),
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

        has_go_artifacts = bool(
            compiler_version or packages or vendor_pkgs or types
        )
        result["is_go_binary"] = has_go_artifacts

        return result
    finally:
        if hasattr(f, "close"):
            f.close()


def main():
    try:
        cmd = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError) as exc:
        json.dump({"error": f"Invalid JSON input: {exc}"}, sys.stdout)
        sys.exit(1)

    filepath = cmd.get("filepath", "")
    limit = cmd.get("limit", 20)
    func_cap = cmd.get("func_cap", 10)
    method_cap = cmd.get("method_cap", 10)

    if not filepath:
        json.dump({"error": "No filepath provided"}, sys.stdout)
        sys.exit(1)

    try:
        result = run_pygore(filepath, limit, func_cap, method_cap)
        json.dump(result, sys.stdout)
    except Exception as exc:
        json.dump({"error": str(exc)[:500]}, sys.stdout)
        sys.exit(1)


if __name__ == "__main__":
    main()
