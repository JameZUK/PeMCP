"""MCP tool for batch/multi-file analysis — compares multiple PE samples."""
import asyncio
import datetime
import hashlib
import os

from typing import Dict, Any, Optional, List

from arkana.config import state, logger, Context, pefile
from arkana.imports import PPDEEP_AVAILABLE, TLSH_AVAILABLE
from arkana.mcp.server import tool_decorator, _check_mcp_response_size

if PPDEEP_AVAILABLE:
    import ppdeep
if TLSH_AVAILABLE:
    import tlsh


MAX_BATCH_FILES = 50
_MAX_TOTAL_BATCH_SIZE = 2 * 1024 * 1024 * 1024  # M1-v9: 2GB total batch limit

# Magic bytes for supported binary formats
_BINARY_MAGIC = {
    b"MZ": "PE",
    b"\x7fELF": "ELF",
    b"\xfe\xed\xfa\xce": "Mach-O",
    b"\xce\xfa\xed\xfe": "Mach-O",
    b"\xfe\xed\xfa\xcf": "Mach-O 64",
    b"\xcf\xfa\xed\xfe": "Mach-O 64",
}


def _is_binary_file(filepath):
    """Quick check if a file looks like a PE/ELF/Mach-O binary."""
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
        for sig in _BINARY_MAGIC:
            if magic[:len(sig)] == sig:
                return True
    except Exception:
        logger.debug("_is_binary_file: cannot read %s", filepath)
    return False


def _parse_single_file(filepath):
    """Parse a single PE file and extract key metadata for comparison."""
    entry = {
        "filename": os.path.basename(filepath),  # L3-v9: no full path in response
        "size": 0,
    }

    _MAX_BATCH_FILE_SIZE = 200 * 1024 * 1024  # 200 MB

    try:
        entry["size"] = os.path.getsize(filepath)
    except OSError as e:
        entry["error"] = f"Cannot stat file: {e}"
        return entry

    if entry["size"] > _MAX_BATCH_FILE_SIZE:
        entry["error"] = f"File too large ({entry['size']} bytes). Maximum is {_MAX_BATCH_FILE_SIZE} bytes."
        return entry

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        entry["error"] = f"Cannot read file: {e}"
        return entry

    # Hashes
    entry["md5"] = hashlib.md5(data).hexdigest()
    entry["sha256"] = hashlib.sha256(data).hexdigest()

    # Similarity hashes (optional)
    if PPDEEP_AVAILABLE:
        try:
            entry["ssdeep"] = ppdeep.hash(data)
        except Exception:
            logger.debug("ssdeep hash failed for %s", filepath)
    if TLSH_AVAILABLE:
        try:
            h = tlsh.hash(data)
            entry["tlsh"] = h if h else None
        except Exception:
            logger.debug("TLSH hash failed for %s", filepath)

    # Release raw bytes after hashing — PE object works from its own copy
    del data

    # M4-v9: PE parsing with try/finally for reliable cleanup
    pe = None
    try:
        with open(filepath, "rb") as f:
            pe_data = f.read()
        pe = pefile.PE(data=pe_data, fast_load=True)
        del pe_data  # Release raw bytes immediately
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ])

        entry["machine"] = hex(pe.FILE_HEADER.Machine)
        entry["timestamp"] = pe.FILE_HEADER.TimeDateStamp
        entry["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        entry["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
        entry["subsystem"] = pe.OPTIONAL_HEADER.Subsystem

        # Sections
        sections = []
        for sec in pe.sections:
            sec_name = sec.Name.rstrip(b'\x00').decode('ascii', 'replace')
            sections.append({
                "name": sec_name,
                "virtual_size": sec.Misc_VirtualSize,
                "entropy": round(sec.get_entropy(), 2),
            })
        entry["sections"] = sections

        # Imports
        imports = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for imp in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = imp.dll.decode('ascii', 'replace').lower()
                funcs = []
                for func in imp.imports:
                    if func.name:
                        funcs.append(func.name.decode('ascii', 'replace'))
                imports[dll_name] = funcs
        entry["imports"] = imports
        entry["import_dlls"] = sorted(imports.keys())
        entry["total_imports"] = sum(len(v) for v in imports.values())

        # Exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            exports = []
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode('ascii', 'replace'))
            entry["exports"] = exports[:50]
            if len(exports) > 50:
                entry["exports_pagination"] = {"total": len(exports), "returned": 50, "has_more": True}
    except Exception as e:
        entry["pe_error"] = f"PE parse failed: {e}"
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                logger.debug("pe.close() failed for %s", filepath)

    return entry


def _compare_files(results, include_similarity):
    """Cross-file comparison: import overlaps, timestamps, similarity clustering."""
    comparison = {}

    valid = [r for r in results if "pe_error" not in r and "error" not in r]
    if len(valid) < 2:
        comparison["note"] = "Need at least 2 valid PE files for comparison."
        return comparison

    # ---- Import DLL overlap ----
    all_dll_sets = {}
    for r in valid:
        all_dll_sets[r["filename"]] = set(r.get("import_dlls", []))

    if all_dll_sets:
        common_dlls = set.intersection(*all_dll_sets.values())
        all_dlls = set.union(*all_dll_sets.values())
        comparison["import_overlap"] = {
            "common_dlls": sorted(common_dlls),
            "total_unique_dlls": len(all_dlls),
            "overlap_ratio": round(len(common_dlls) / len(all_dlls), 2) if all_dlls else 0,
        }

    # ---- Import function overlap ----
    func_counts = {}
    for r in valid:
        for dll, funcs in r.get("imports", {}).items():
            for func in funcs:
                key = f"{dll}:{func}"
                func_counts[key] = func_counts.get(key, 0) + 1

    n_files = len(valid)
    shared_funcs = sorted(k for k, v in func_counts.items() if v == n_files)
    unique_funcs_count = sum(1 for v in func_counts.values() if v == 1)
    comparison["shared_imports"] = shared_funcs[:30]
    if len(shared_funcs) > 30:
        comparison["shared_imports_pagination"] = {"total": len(shared_funcs), "returned": 30, "has_more": True}
    comparison["unique_imports_count"] = unique_funcs_count

    # ---- Timestamp analysis ----
    timestamps = [(r["filename"], r.get("timestamp", 0)) for r in valid if r.get("timestamp")]
    if timestamps:
        ts_values = [t for _, t in timestamps]
        comparison["timestamps"] = {
            "files": [{
                "file": f,
                "timestamp": t,
                "date": (datetime.datetime.fromtimestamp(t, tz=datetime.timezone.utc).isoformat()
                         if 946684800 < t < 2000000000 else "invalid"),
            } for f, t in timestamps],
            "all_identical": len(set(ts_values)) == 1,
            "spread_seconds": max(ts_values) - min(ts_values) if len(ts_values) > 1 else 0,
        }

    # ---- Size comparison ----
    sizes = [(r["filename"], r["size"]) for r in valid]
    comparison["sizes"] = {
        "identical_size": len(set(s for _, s in sizes)) == 1,
        "min": min(s for _, s in sizes),
        "max": max(s for _, s in sizes),
    }

    # ---- High entropy sections ----
    high_entropy = []
    for r in valid:
        for sec in r.get("sections", []):
            if sec.get("entropy", 0) > 7.0:
                high_entropy.append({
                    "file": r["filename"],
                    "section": sec["name"],
                    "entropy": sec["entropy"],
                })
    if high_entropy:
        comparison["high_entropy_sections"] = high_entropy[:20]
        if len(high_entropy) > 20:
            comparison["high_entropy_sections_pagination"] = {"total": len(high_entropy), "returned": 20, "has_more": True}

    # ---- Similarity clustering ----
    if include_similarity and len(valid) >= 2:
        similarity = {}

        # Identical files (same SHA256)
        hash_groups = {}
        for r in valid:
            h = r.get("sha256")
            if h:
                hash_groups.setdefault(h, []).append(r["filename"])
        duplicates = {h: files for h, files in hash_groups.items() if len(files) > 1}
        if duplicates:
            similarity["identical_files"] = duplicates

        # ssdeep pairwise
        if PPDEEP_AVAILABLE:
            ssdeep_pairs = []
            for i, a in enumerate(valid):
                for b in valid[i + 1:]:
                    if a.get("ssdeep") and b.get("ssdeep"):
                        try:
                            score = ppdeep.compare(a["ssdeep"], b["ssdeep"])
                            if score > 0:
                                ssdeep_pairs.append({
                                    "file_a": a["filename"],
                                    "file_b": b["filename"],
                                    "score": score,
                                })
                        except Exception:
                            logger.debug("ssdeep compare failed: %s vs %s", a["filename"], b["filename"])
            ssdeep_pairs.sort(key=lambda x: -x["score"])
            if ssdeep_pairs:
                similarity["ssdeep_pairs"] = ssdeep_pairs[:20]
                if len(ssdeep_pairs) > 20:
                    similarity["ssdeep_pairs_pagination"] = {"total": len(ssdeep_pairs), "returned": 20, "has_more": True}

        # TLSH pairwise
        if TLSH_AVAILABLE:
            tlsh_pairs = []
            for i, a in enumerate(valid):
                for b in valid[i + 1:]:
                    if a.get("tlsh") and b.get("tlsh"):
                        try:
                            distance = tlsh.diff(a["tlsh"], b["tlsh"])
                            tlsh_pairs.append({
                                "file_a": a["filename"],
                                "file_b": b["filename"],
                                "distance": distance,
                                "verdict": ("very similar" if distance < 30
                                            else "similar" if distance < 100
                                            else "different"),
                            })
                        except Exception:
                            logger.debug("TLSH diff failed: %s vs %s", a["filename"], b["filename"])
            tlsh_pairs.sort(key=lambda x: x["distance"])
            if tlsh_pairs:
                similarity["tlsh_pairs"] = tlsh_pairs[:20]
                if len(tlsh_pairs) > 20:
                    similarity["tlsh_pairs_pagination"] = {"total": len(tlsh_pairs), "returned": 20, "has_more": True}

        if similarity:
            comparison["similarity"] = similarity

    return comparison


# ===================================================================
#  analyze_batch
# ===================================================================

@tool_decorator
async def analyze_batch(
    ctx: Context,
    directory: Optional[str] = None,
    file_paths: Optional[List[str]] = None,
    include_similarity: bool = True,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: utility] Batch-analyzes multiple binary files: computes hashes, PE
    metadata, import overlaps, timestamp comparison, and optional similarity
    clustering (ssdeep/TLSH pairwise). Does NOT modify the currently loaded file.

    When to use: When comparing a set of samples (malware family variants,
    dropper artifacts, a samples directory) to identify commonalities, outliers,
    and cluster related files.

    Provide either `directory` (auto-discovers PE files) or `file_paths` (explicit list).

    Next steps: open_file() on interesting samples for deep analysis. Use
    compute_similarity_hashes() / compare_file_similarity() for targeted
    pairwise comparison of specific files.

    Args:
        directory: Path to a directory containing binary files to analyze.
            Only files with PE/ELF/Mach-O magic bytes are included.
        file_paths: Explicit list of file paths to analyze.
        include_similarity: If True, compute ssdeep/TLSH similarity hashes
            and pairwise comparison. Requires ppdeep and/or py-tlsh.
        limit: Max files to analyze (default 20, max 50).
    """
    if not directory and not file_paths:
        raise ValueError("Provide either 'directory' or 'file_paths'.")

    limit = min(limit, MAX_BATCH_FILES)

    # Resolve file list
    paths = []
    if file_paths:
        for p in file_paths[:limit]:
            abs_p = os.path.realpath(p)
            state.check_path_allowed(abs_p)
            if os.path.isfile(abs_p):
                paths.append(abs_p)
    elif directory:
        abs_dir = os.path.realpath(directory)
        state.check_path_allowed(abs_dir)
        if not os.path.isdir(abs_dir):
            raise ValueError(f"Directory not found: {directory}")
        for fname in sorted(os.listdir(abs_dir)):
            fpath = os.path.join(abs_dir, fname)
            if os.path.isfile(fpath) and _is_binary_file(fpath):
                paths.append(fpath)
            if len(paths) >= limit:
                break

    if not paths:
        return {"error": "No binary files found to analyze.",
                "directory": directory, "file_paths": file_paths}

    # M1-v9: Total batch size limit to prevent excessive memory usage
    total_size = sum(os.path.getsize(p) for p in paths if os.path.isfile(p))
    if total_size > _MAX_TOTAL_BATCH_SIZE:
        raise ValueError(
            f"Total batch size ({total_size / (1024**3):.1f}GB) exceeds limit "
            f"({_MAX_TOTAL_BATCH_SIZE // (1024**3)}GB)."
        )

    await ctx.info(f"Batch analyzing {len(paths)} files")
    await ctx.report_progress(5, 100)

    def _do_analysis():
        file_results = []
        for fpath in paths:
            file_results.append(_parse_single_file(fpath))
        comparison = _compare_files(file_results, include_similarity)
        return file_results, comparison

    file_results, comparison = await asyncio.to_thread(_do_analysis)
    await ctx.report_progress(95, 100)

    # Strip full import lists from per-file entries to save space —
    # the comparison section has the cross-file analysis
    for r in file_results:
        if "imports" in r:
            del r["imports"]

    output = {
        "files_analyzed": len(file_results),
        "files": file_results,
        "comparison": comparison,
        "similarity_libs": {
            "ppdeep": PPDEEP_AVAILABLE,
            "tlsh": TLSH_AVAILABLE,
        },
    }

    return await _check_mcp_response_size(ctx, output, "analyze_batch", "the 'limit' parameter")
