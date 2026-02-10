"""MCP tools for Rust binary analysis."""
import asyncio
from typing import Dict, Any, Optional, List
from pemcp.config import state, logger, Context
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size
from pemcp.mcp._format_helpers import _check_lib, _get_filepath

RUSTBININFO_AVAILABLE = False
try:
    import rustbininfo
    RUSTBININFO_AVAILABLE = True
except ImportError:
    pass

RUST_DEMANGLER_AVAILABLE = False
try:
    import rust_demangler
    RUST_DEMANGLER_AVAILABLE = True
except ImportError:
    pass


@tool_decorator
async def rust_analyze(
    ctx: Context,
    file_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Extracts Rust binary metadata: compiler version, crate dependencies
    (name, version, features), toolchain, and dependencies imphash.

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
        else:
            # Fallback: try the RustBinaryInfo class
            try:
                rbi = rustbininfo.RustBinaryInfo(target) if hasattr(rustbininfo, 'RustBinaryInfo') else None
                if rbi:
                    result["is_rust_binary"] = True
                    result["compiler_version"] = str(rbi.compiler_version) if hasattr(rbi, 'compiler_version') else None
                    result["dependencies"] = [str(d) for d in rbi.dependencies] if hasattr(rbi, 'dependencies') else []
                else:
                    result["is_rust_binary"] = False
                    result["note"] = "Could not detect Rust metadata in this binary."
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
