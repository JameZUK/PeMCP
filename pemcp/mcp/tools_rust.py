"""MCP tools for Rust binary analysis."""
import asyncio
import re
from typing import Dict, Any, Optional, List
from pemcp.config import state, logger, Context, RUSTBININFO_AVAILABLE, RUST_DEMANGLER_AVAILABLE
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size
from pemcp.mcp._format_helpers import _check_lib, _get_filepath

if RUSTBININFO_AVAILABLE:
    import rustbininfo
if RUST_DEMANGLER_AVAILABLE:
    import rust_demangler


def _rust_string_scan(filepath: str, scan_limit: int = 2 * 1024 * 1024) -> Dict[str, Any]:
    """Fallback Rust detection by scanning binary for Rust-specific strings.

    Works on stripped binaries where rustbininfo cannot find metadata.
    Returns a dict with detection results and any extracted info.
    """
    markers_found = []
    rustc_version = None
    rust_symbols = []

    with open(filepath, 'rb') as f:
        data = f.read(scan_limit)

    # Check for known Rust markers
    marker_checks = [
        (b'rust_begin_unwind', "rust_begin_unwind (panic handler)"),
        (b'rust_panic', "rust_panic"),
        (b'rust_eh_personality', "rust_eh_personality (exception handling)"),
        (b'__rust_alloc', "__rust_alloc (Rust allocator)"),
        (b'__rust_dealloc', "__rust_dealloc"),
        (b'core::panicking', "core::panicking"),
        (b'core::result::Result', "core::result::Result"),
        (b'core::option::Option', "core::option::Option"),
        (b'alloc::string::String', "alloc::string::String"),
        (b'alloc::vec::Vec', "alloc::vec::Vec"),
        (b'std::rt::lang_start', "std::rt::lang_start (Rust entry point)"),
        (b'std::io::stdio', "std::io::stdio"),
        (b'.rustc', ".rustc section"),
        (b'rustc/', "rustc version marker"),
    ]

    for marker_bytes, description in marker_checks:
        if marker_bytes in data:
            markers_found.append(description)

    # Try to extract rustc version string (e.g. "rustc/1.75.0" or "rustc 1.75.0")
    version_patterns = [
        rb'rustc[/ ](\d+\.\d+\.\d+[^\x00\n]*)',
        rb'rustc version (\d+\.\d+\.\d+[^\x00\n]*)',
    ]
    for pat in version_patterns:
        match = re.search(pat, data)
        if match:
            try:
                rustc_version = match.group(1).decode('utf-8', 'ignore').strip()[:100]
            except Exception:
                pass
            break

    # Extract Rust-mangled symbols (look for _ZN...E pattern or _R prefix)
    # Limit to first 50 for performance
    mangled_pattern = rb'(_(?:ZN|R)[A-Za-z0-9_$]{10,200}E?)'
    for match in re.finditer(mangled_pattern, data):
        if len(rust_symbols) >= 50:
            break
        sym = match.group(1).decode('ascii', 'ignore')
        # Quick heuristic: Rust mangled names contain "core" "alloc" "std" fragments
        if any(frag in sym for frag in ('3std', '4core', '5alloc', '3vec', '6string')):
            rust_symbols.append(sym)

    is_rust = len(markers_found) >= 2 or rustc_version is not None

    return {
        "is_rust_binary": is_rust,
        "detection_method": "string_scan" if is_rust else None,
        "markers_found": markers_found,
        "marker_count": len(markers_found),
        "rustc_version": rustc_version,
        "mangled_symbols_found": len(rust_symbols),
        "sample_mangled_symbols": rust_symbols[:10],
    }


@tool_decorator
async def rust_analyze(
    ctx: Context,
    file_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Extracts Rust binary metadata: compiler version, crate dependencies
    (name, version, features), toolchain, and dependencies imphash.
    Falls back to string-based detection for stripped binaries.

    Args:
        file_path: Optional path to a Rust binary. If None, uses the loaded file.
    """
    await ctx.info("Analysing Rust binary")
    _check_lib("rustbininfo", RUSTBININFO_AVAILABLE, "rust_analyze")
    target = _get_filepath(file_path)

    def _parse():
        try:
            info = rustbininfo.get_info(target) if hasattr(rustbininfo, 'get_info') else None
        except Exception:
            info = None

        result: Dict[str, Any] = {"file": target}

        # Try various API shapes since rustbininfo evolves
        if info:
            result["is_rust_binary"] = True
            result["detection_method"] = "rustbininfo_metadata"
            if hasattr(info, 'compiler_version'):
                result["compiler_version"] = str(info.compiler_version)
            if hasattr(info, 'rustc_commit_hash'):
                result["rustc_commit_hash"] = str(info.rustc_commit_hash)
            if hasattr(info, 'toolchain'):
                result["toolchain"] = str(info.toolchain)
            if hasattr(info, 'dependencies'):
                deps = []
                for dep in info.dependencies:
                    deps.append({
                        "name": dep.name if hasattr(dep, 'name') else str(dep),
                        "version": str(dep.version) if hasattr(dep, 'version') else None,
                    })
                result["dependencies"] = deps
                result["dependency_count"] = len(deps)
            if hasattr(info, 'deps_imphash'):
                result["dependencies_imphash"] = str(info.deps_imphash)
            return result

        # Fallback: try the RustBinaryInfo class
        try:
            rbi = rustbininfo.RustBinaryInfo(target) if hasattr(rustbininfo, 'RustBinaryInfo') else None
            if rbi:
                result["is_rust_binary"] = True
                result["detection_method"] = "rustbininfo_class"
                result["compiler_version"] = str(rbi.compiler_version) if hasattr(rbi, 'compiler_version') else None
                result["dependencies"] = [str(d) for d in rbi.dependencies] if hasattr(rbi, 'dependencies') else []
                return result
        except Exception:
            pass

        # Final fallback: string-based scanning for stripped binaries
        try:
            scan_result = _rust_string_scan(target)
            result.update(scan_result)
            if scan_result["is_rust_binary"]:
                result["note"] = (
                    "Detected as Rust via string patterns (stripped binary — no crate metadata). "
                    "Use rust_demangle_symbols on the sample symbols for readable names."
                )
            else:
                result["note"] = "Could not detect Rust metadata or markers in this binary."
        except Exception as e:
            result["is_rust_binary"] = False
            result["error"] = f"Rust analysis failed: {e}"

        return result

    result = await asyncio.to_thread(_parse)
    return await _check_mcp_response_size(ctx, result, "rust_analyze")


@tool_decorator
async def rust_demangle_symbols(
    ctx: Context,
    symbols: List[str],
    limit: int = 200,
) -> Dict[str, Any]:
    """
    Demangles Rust symbol names to human-readable form.
    e.g. '_ZN3foo3bar17h05af221e174051e8E' -> 'foo::bar'

    Args:
        symbols: List of mangled Rust symbol names.
        limit: Max symbols to return.
    """
    await ctx.info(f"Demangling {len(symbols)} Rust symbols")
    _check_lib("rust_demangler", RUST_DEMANGLER_AVAILABLE, "rust_demangle_symbols", "rust-demangler")

    def _demangle():
        results = []
        for sym in symbols[:limit]:
            try:
                demangled = rust_demangler.demangle(sym)
                results.append({"mangled": sym, "demangled": demangled})
            except Exception:
                results.append({"mangled": sym, "demangled": sym, "note": "could not demangle"})
        return results

    demangled = await asyncio.to_thread(_demangle)
    return {
        "total": len(demangled),
        "symbols": demangled,
    }
