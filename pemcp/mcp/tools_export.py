"""MCP tools for exporting and importing PeMCP project archives."""
import gzip
import io
import json
import os
import shutil
import tarfile
import tempfile

from pathlib import Path
from typing import Dict, Any, Optional

from pemcp.config import state, logger, Context, analysis_cache
from pemcp.mcp.server import tool_decorator, _check_pe_loaded
from pemcp.cache import CACHE_DIR

try:
    from pemcp import __version__ as PEMCP_VERSION
except ImportError:
    PEMCP_VERSION = "unknown"

# Extension for project archives
PROJECT_EXTENSION = ".pemcp_project.tar.gz"

# Directory for imported binaries when no explicit path is given
IMPORT_DIR = Path.home() / ".pemcp" / "imported"


@tool_decorator
async def export_project(
    ctx: Context,
    output_path: str,
    include_binary: bool = True,
) -> Dict[str, Any]:
    """
    Export the current session as a portable project archive (.pemcp_project.tar.gz).
    Includes analysis data, notes, tool history, and optionally the original binary.

    The archive can be shared with others and imported with import_project to
    restore the full analysis context.

    Args:
        ctx: The MCP Context object.
        output_path: (str) Path for the output archive file.
        include_binary: (bool) If True (default), include the original binary file.

    Returns:
        A dictionary with export status, archive path, and size.
    """
    _check_pe_loaded("export_project")

    # Ensure output path ends with proper extension
    if not output_path.endswith(PROJECT_EXTENSION):
        if output_path.endswith(".tar.gz"):
            output_path = output_path[:-7] + PROJECT_EXTENSION
        else:
            output_path = output_path + PROJECT_EXTENSION

    abs_output = str(Path(output_path).resolve())
    state.check_path_allowed(abs_output)

    hashes = (state.pe_data.get("file_hashes") or {})
    sha256 = hashes.get("sha256", "unknown")
    original_filename = os.path.basename(state.filepath) if state.filepath else "unknown"

    # Build manifest
    manifest = {
        "pemcp_version": PEMCP_VERSION,
        "export_version": 1,
        "created_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
        "sha256": sha256,
        "original_filename": original_filename,
        "mode": state.pe_data.get("mode", "unknown"),
        "binary_included": include_binary and state.filepath is not None and os.path.isfile(state.filepath),
        "notes_count": len(state.get_all_notes_snapshot()),
        "tool_history_count": len(state.get_tool_history_snapshot()),
    }

    # Build the cache wrapper (same format as disk cache)
    wrapper = {
        "_cache_meta": {
            "cache_format_version": 1,
            "pemcp_version": PEMCP_VERSION,
            "sha256": sha256,
            "original_filename": original_filename,
            "original_file_size": os.path.getsize(state.filepath) if state.filepath and os.path.isfile(state.filepath) else None,
            "mode": state.pe_data.get("mode", "unknown"),
        },
        "pe_data": {k: v for k, v in state.pe_data.items() if k != "filepath"},
        "notes": state.get_all_notes_snapshot(),
        "tool_history": state.get_tool_history_snapshot(),
    }

    await ctx.info(f"Creating project archive: {abs_output}")

    # Create the tar.gz archive
    output_dir = os.path.dirname(abs_output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with tarfile.open(abs_output, "w:gz") as tar:
        # Add manifest.json
        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        manifest_info = tarfile.TarInfo(name="manifest.json")
        manifest_info.size = len(manifest_bytes)
        tar.addfile(manifest_info, io.BytesIO(manifest_bytes))

        # Add analysis.json.gz (gzip-compressed wrapper)
        wrapper_json = json.dumps(wrapper).encode("utf-8")
        wrapper_gz = gzip.compress(wrapper_json)
        analysis_info = tarfile.TarInfo(name="analysis.json.gz")
        analysis_info.size = len(wrapper_gz)
        tar.addfile(analysis_info, io.BytesIO(wrapper_gz))

        # Optionally add the binary
        if manifest["binary_included"]:
            binary_path = state.filepath
            binary_name = f"binary/{original_filename}"
            tar.add(binary_path, arcname=binary_name)
            await ctx.info(f"Binary included: {original_filename}")

    archive_size = os.path.getsize(abs_output)
    await ctx.info(f"Project exported: {archive_size / 1024:.1f} KB")

    return {
        "status": "success",
        "archive_path": abs_output,
        "archive_size_kb": round(archive_size / 1024, 1),
        "binary_included": manifest["binary_included"],
        "notes_count": manifest["notes_count"],
        "tool_history_count": manifest["tool_history_count"],
        "sha256": sha256,
    }


@tool_decorator
async def import_project(
    ctx: Context,
    project_path: str,
    load_binary: bool = True,
) -> Dict[str, Any]:
    """
    Import a previously exported project archive (.pemcp_project.tar.gz).
    Restores analysis data, notes, and tool history into the cache.
    Optionally extracts and loads the embedded binary.

    Args:
        ctx: The MCP Context object.
        project_path: (str) Path to the .pemcp_project.tar.gz archive.
        load_binary: (bool) If True (default) and the archive includes a binary,
            extract it and load it.

    Returns:
        A dictionary with import status, restored file info, note count,
        and history count.
    """
    abs_path = str(Path(project_path).resolve())
    state.check_path_allowed(abs_path)

    if not os.path.isfile(abs_path):
        raise RuntimeError(f"[import_project] Archive not found: {abs_path}")

    await ctx.info(f"Importing project archive: {abs_path}")

    manifest = None
    wrapper = None
    binary_data = None
    binary_name = None

    # Extract archive contents
    with tarfile.open(abs_path, "r:gz") as tar:
        # Security: validate member names to prevent path traversal
        for member in tar.getmembers():
            if member.name.startswith("/") or ".." in member.name:
                raise RuntimeError(
                    f"[import_project] Unsafe archive member: '{member.name}'. "
                    "Archive may have been tampered with."
                )

        # Read manifest
        try:
            manifest_file = tar.extractfile("manifest.json")
            if manifest_file:
                manifest = json.loads(manifest_file.read().decode("utf-8"))
        except (KeyError, json.JSONDecodeError) as e:
            raise RuntimeError(f"[import_project] Invalid archive: cannot read manifest.json: {e}")

        if not manifest:
            raise RuntimeError("[import_project] Invalid archive: missing manifest.json")

        export_version = manifest.get("export_version", 0)
        if export_version != 1:
            raise RuntimeError(
                f"[import_project] Unsupported export version: {export_version}. "
                f"This version of PeMCP supports export version 1."
            )

        # Read analysis data
        try:
            analysis_file = tar.extractfile("analysis.json.gz")
            if analysis_file:
                analysis_gz = analysis_file.read()
                wrapper = json.loads(gzip.decompress(analysis_gz).decode("utf-8"))
        except (KeyError, gzip.BadGzipFile, json.JSONDecodeError) as e:
            raise RuntimeError(f"[import_project] Invalid archive: cannot read analysis.json.gz: {e}")

        if not wrapper:
            raise RuntimeError("[import_project] Invalid archive: missing analysis.json.gz")

        # Read binary if present and requested
        if manifest.get("binary_included") and load_binary:
            binary_prefix = "binary/"
            for member in tar.getmembers():
                if member.name.startswith(binary_prefix) and member.isfile():
                    binary_name = member.name[len(binary_prefix):]
                    bf = tar.extractfile(member)
                    if bf:
                        binary_data = bf.read()
                    break

    sha256 = manifest.get("sha256", "").lower()

    # Store the analysis data in the cache
    if sha256 and len(sha256) == 64:
        cache_entry_dir = CACHE_DIR / sha256[:2]
        cache_entry_dir.mkdir(parents=True, exist_ok=True)
        cache_entry_path = cache_entry_dir / f"{sha256}.json.gz"

        # Write the wrapper directly as a cache entry
        with gzip.open(cache_entry_path, "wt", encoding="utf-8") as f:
            json.dump(wrapper, f)

        # Update cache metadata
        analysis_cache._lock.acquire()
        try:
            meta = analysis_cache._load_meta()
            meta[sha256] = {
                "original_filename": manifest.get("original_filename", "imported"),
                "cached_at": __import__("time").time(),
                "last_accessed": __import__("time").time(),
                "size_bytes": cache_entry_path.stat().st_size,
                "mode": manifest.get("mode", "unknown"),
            }
            analysis_cache._save_meta(meta)
        finally:
            analysis_cache._lock.release()

        await ctx.info(f"Analysis data imported into cache (SHA256: {sha256[:16]}...)")

    result: Dict[str, Any] = {
        "status": "success",
        "sha256": sha256,
        "original_filename": manifest.get("original_filename"),
        "mode": manifest.get("mode"),
        "notes_count": manifest.get("notes_count", 0),
        "tool_history_count": manifest.get("tool_history_count", 0),
        "binary_included": manifest.get("binary_included", False),
    }

    # Extract binary and load it
    if binary_data and binary_name:
        IMPORT_DIR.mkdir(parents=True, exist_ok=True)
        binary_path = IMPORT_DIR / binary_name
        binary_path.write_bytes(binary_data)

        result["binary_extracted_to"] = str(binary_path)
        result["hint"] = f"Binary extracted to {binary_path}. Call open_file('{binary_path}') to load it (will use the imported cache)."
        await ctx.info(f"Binary extracted to: {binary_path}")
    elif not manifest.get("binary_included"):
        result["hint"] = (
            "No binary was included in the archive. Notes and history are "
            "cached by SHA256 — they will be restored when the matching "
            "binary is opened with open_file."
        )

    return result
