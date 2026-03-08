"""MCP tools for exporting and importing Arkana project archives."""
import gzip
import io
import json
import os
import re
import shutil
import tarfile
import tempfile

from pathlib import Path
from typing import Dict, Any, Optional

from arkana.config import state, logger, Context, analysis_cache
from arkana.constants import MAX_TOTAL_ARTIFACT_EXPORT_SIZE
from arkana.mcp.server import tool_decorator, _check_pe_loaded
from arkana.cache import CACHE_DIR
from arkana.utils import _safe_env_int

try:
    from arkana import __version__ as ARKANA_VERSION
except ImportError:
    ARKANA_VERSION = "unknown"

# Extension for project archives (import accepts both old and new extensions)
PROJECT_EXTENSION = ".arkana_project.tar.gz"

# Directory for imported binaries when no explicit path is given
IMPORT_DIR = Path.home() / ".arkana" / "imported"

# Maximum size of a single imported binary (default 256 MB)
_MAX_IMPORT_BINARY_SIZE = _safe_env_int("ARKANA_MAX_FILE_SIZE_MB", _safe_env_int("PEMCP_MAX_FILE_SIZE_MB", 256)) * 1024 * 1024

# Maximum total size of all imported binaries (default 1 GB)
_MAX_IMPORT_DIR_SIZE = _safe_env_int("ARKANA_MAX_IMPORT_DIR_SIZE_MB", _safe_env_int("PEMCP_MAX_IMPORT_DIR_SIZE_MB", 1024)) * 1024 * 1024

# Maximum decompressed analysis.json.gz size (256 MB)
_MAX_ANALYSIS_DECOMPRESSED_SIZE = 256 * 1024 * 1024

# Regex for sanitizing binary filenames
_SAFE_FILENAME_RE = re.compile(r'[^a-zA-Z0-9._\-]')


@tool_decorator
async def export_project(
    ctx: Context,
    output_path: str,
    include_binary: bool = True,
) -> Dict[str, Any]:
    """
    [Phase: utility] Export the current session as a portable project archive
    (.arkana_project.tar.gz). Includes analysis data, notes, tool history,
    and optionally the original binary.

    When to use: When sharing analysis with others or preserving a checkpoint
    of your work. The archive can be imported with import_project().

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

    artifacts_snapshot = state.get_all_artifacts_snapshot()

    # Build manifest
    manifest = {
        "arkana_version": ARKANA_VERSION,
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
        "artifacts_count": len(artifacts_snapshot),
        "renames_count": sum(len(v) for v in state.get_all_renames_snapshot().values()),
        "custom_types_count": sum(len(v) for v in state.get_all_types_snapshot().values()),
    }

    # Build the cache wrapper (same format as disk cache)
    wrapper = {
        "_cache_meta": {
            "cache_format_version": 1,
            "arkana_version": ARKANA_VERSION,
            "sha256": sha256,
            "original_filename": original_filename,
            "original_file_size": os.path.getsize(state.filepath) if state.filepath and os.path.isfile(state.filepath) else None,
            "mode": state.pe_data.get("mode", "unknown"),
        },
        "pe_data": {k: v for k, v in state.pe_data.items() if k != "filepath"},
        "notes": state.get_all_notes_snapshot(),
        "tool_history": state.get_tool_history_snapshot(),
        "artifacts": artifacts_snapshot,
        "renames": state.get_all_renames_snapshot(),
        "custom_types": state.get_all_types_snapshot(),
    }

    await ctx.info(f"Creating project archive: {abs_output}")

    # Create the tar.gz archive
    output_dir = os.path.dirname(abs_output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    artifacts_included = 0
    artifacts_total_size = 0

    with tarfile.open(abs_output, "w:gz") as tar:
        # Add manifest.json
        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        manifest_info = tarfile.TarInfo(name="manifest.json")
        manifest_info.size = len(manifest_bytes)
        tar.addfile(manifest_info, io.BytesIO(manifest_bytes))

        # Add analysis.json.gz (gzip-compressed wrapper)
        wrapper_json = json.dumps(wrapper).encode("utf-8")
        if len(wrapper_json) > 256 * 1024 * 1024:
            raise RuntimeError(
                f"Serialised analysis data is too large ({len(wrapper_json) // (1024 * 1024)} MB). "
                "Maximum supported size is 256 MB. Try exporting without the binary or reducing analysis scope."
            )
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

        # Add artifact files
        for artifact in artifacts_snapshot:
            art_path = artifact.get("path", "")
            art_size = artifact.get("size", 0)
            if not art_path or not os.path.isfile(art_path):
                logger.warning("Artifact file not found, skipping: %s", art_path)
                continue
            if artifacts_total_size + art_size > MAX_TOTAL_ARTIFACT_EXPORT_SIZE:
                logger.warning(
                    "Artifact export size limit reached (%d MB). Skipping: %s",
                    MAX_TOTAL_ARTIFACT_EXPORT_SIZE // (1024 * 1024), art_path,
                )
                continue
            arcname = f"artifacts/{os.path.basename(art_path)}"
            tar.add(art_path, arcname=arcname)
            artifacts_included += 1
            artifacts_total_size += art_size

    archive_size = os.path.getsize(abs_output)
    await ctx.info(f"Project exported: {archive_size / 1024:.1f} KB")

    return {
        "status": "success",
        "archive_path": abs_output,
        "archive_size_kb": round(archive_size / 1024, 1),
        "binary_included": manifest["binary_included"],
        "notes_count": manifest["notes_count"],
        "tool_history_count": manifest["tool_history_count"],
        "artifacts_count": artifacts_included,
        "artifacts_total_size_kb": round(artifacts_total_size / 1024, 1),
        "sha256": sha256,
    }


@tool_decorator
async def import_project(
    ctx: Context,
    project_path: str,
    load_binary: bool = True,
) -> Dict[str, Any]:
    """
    [Phase: load] Import a previously exported project archive
    (.arkana_project.tar.gz). Restores analysis data, notes, and tool history.

    When to use: When resuming analysis from a shared archive or a previous
    checkpoint. Optionally extracts and loads the embedded binary.

    Next steps: open_file() to load the restored binary, then
    get_analysis_digest() to review what was learned in the exported session.

    Args:
        ctx: The MCP Context object.
        project_path: (str) Path to the .arkana_project.tar.gz archive.
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
    artifact_files = {}  # basename -> bytes

    # Extract archive contents
    with tarfile.open(abs_path, "r:gz") as tar:
        # Security: validate member names to prevent path traversal
        for member in tar.getmembers():
            # C1: Reject symlinks and hardlinks to prevent traversal attacks
            if member.issym() or member.islnk():
                raise RuntimeError(
                    f"[import_project] Archive contains symlink/hardlink: '{member.name}'. "
                    "Archive may have been tampered with."
                )
            norm = os.path.normpath(member.name)
            if (member.name.startswith("/") or norm.startswith("/")
                    or norm.startswith("..") or norm.startswith(os.sep + "..")):
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
                f"This version of Arkana supports export version 1."
            )

        # Read analysis data (with decompression bomb guard)
        try:
            analysis_file = tar.extractfile("analysis.json.gz")
            if analysis_file:
                analysis_gz = analysis_file.read()
                decompressed = gzip.decompress(analysis_gz)
                if len(decompressed) > _MAX_ANALYSIS_DECOMPRESSED_SIZE:
                    raise RuntimeError(
                        f"[import_project] analysis.json.gz decompresses to "
                        f"{len(decompressed) / (1024*1024):.1f} MB — exceeds "
                        f"{_MAX_ANALYSIS_DECOMPRESSED_SIZE // (1024*1024)} MB limit. "
                        "Archive may contain a decompression bomb."
                    )
                wrapper = json.loads(decompressed.decode("utf-8"))
                del decompressed  # free memory
        except (KeyError, gzip.BadGzipFile, json.JSONDecodeError) as e:
            raise RuntimeError(f"[import_project] Invalid archive: cannot read analysis.json.gz: {e}")

        if not wrapper:
            raise RuntimeError("[import_project] Invalid archive: missing analysis.json.gz")

        # Read binary if present and requested
        if manifest.get("binary_included") and load_binary:
            binary_prefix = "binary/"
            for member in tar.getmembers():
                if member.name.startswith(binary_prefix) and member.isfile():
                    # C6: Reject members with subdirectories beyond the prefix
                    relative = member.name[len(binary_prefix):]
                    if "/" in relative or "\\" in relative:
                        raise RuntimeError(
                            f"[import_project] Binary member has subdirectories: '{member.name}'. "
                            "Archive may have been tampered with."
                        )
                    raw_name = os.path.basename(relative)
                    if not raw_name:
                        continue
                    # Enforce size limit BEFORE reading into memory
                    if member.size > _MAX_IMPORT_BINARY_SIZE:
                        raise RuntimeError(
                            f"[import_project] Embedded binary too large "
                            f"({member.size / (1024*1024):.1f} MB). "
                            f"Maximum allowed is {_MAX_IMPORT_BINARY_SIZE // (1024*1024)} MB."
                        )
                    # Sanitize filename to prevent path traversal via special chars
                    binary_name = _SAFE_FILENAME_RE.sub('_', raw_name)
                    if not binary_name or binary_name.startswith('.'):
                        binary_name = f"imported_{binary_name}"
                    bf = tar.extractfile(member)
                    if bf:
                        binary_data = bf.read()
                    break

        # Read artifact files (C6: deduplicate colliding basenames)
        artifact_prefix = "artifacts/"
        seen_basenames: set = set()
        artifact_name_map: dict = {}  # original_basename -> deduped_basename
        for member in tar.getmembers():
            if member.name.startswith(artifact_prefix) and member.isfile():
                relative = member.name[len(artifact_prefix):]
                if "/" in relative or "\\" in relative:
                    logger.warning("Skipping artifact with subdirectory: %s", member.name)
                    continue
                art_basename = os.path.basename(relative)
                if not art_basename:
                    continue
                # Deduplicate collisions by appending counter
                original_basename = art_basename
                counter = 1
                while art_basename in seen_basenames:
                    name, ext = os.path.splitext(original_basename)
                    art_basename = f"{name}_{counter}{ext}"
                    counter += 1
                seen_basenames.add(art_basename)
                artifact_name_map[original_basename] = art_basename
                af = tar.extractfile(member)
                if af:
                    artifact_files[art_basename] = af.read()

    sha256 = manifest.get("sha256", "").lower()

    # Store the analysis data in the cache
    if sha256 and len(sha256) == 64:
        cache_entry_dir = CACHE_DIR / sha256[:2]
        cache_entry_dir.mkdir(parents=True, exist_ok=True)
        cache_entry_path = cache_entry_dir / f"{sha256}.json.gz"

        # Write the wrapper directly as a cache entry
        with gzip.open(cache_entry_path, "wt", encoding="utf-8") as f:
            json.dump(wrapper, f)

        # Update cache metadata via public API
        import time as _time
        analysis_cache.insert_raw_entry(sha256, {
            "original_filename": manifest.get("original_filename", "imported"),
            "cached_at": _time.time(),
            "last_accessed": _time.time(),
            "size_bytes": cache_entry_path.stat().st_size,
            "mode": manifest.get("mode", "unknown"),
        })

        await ctx.info(f"Analysis data imported into cache (SHA256: {sha256[:16]}...)")

    result: Dict[str, Any] = {
        "status": "success",
        "sha256": sha256,
        "original_filename": manifest.get("original_filename"),
        "mode": manifest.get("mode"),
        "notes_count": manifest.get("notes_count", 0),
        "tool_history_count": manifest.get("tool_history_count", 0),
        "artifacts_count": manifest.get("artifacts_count", 0),
        "binary_included": manifest.get("binary_included", False),
    }

    # Extract binary and load it
    if binary_data and binary_name:
        # Enforce per-file size limit
        if len(binary_data) > _MAX_IMPORT_BINARY_SIZE:
            raise RuntimeError(
                f"[import_project] Embedded binary is too large "
                f"({len(binary_data) / (1024*1024):.1f} MB). "
                f"Maximum allowed is {_MAX_IMPORT_BINARY_SIZE // (1024*1024)} MB. "
                "Set ARKANA_MAX_FILE_SIZE_MB to change this limit."
            )
        # Enforce total import directory size limit
        IMPORT_DIR.mkdir(parents=True, exist_ok=True)
        existing_size = sum(f.stat().st_size for f in IMPORT_DIR.iterdir() if f.is_file())
        if existing_size + len(binary_data) > _MAX_IMPORT_DIR_SIZE:
            raise RuntimeError(
                f"[import_project] Import directory would exceed size limit "
                f"({_MAX_IMPORT_DIR_SIZE // (1024*1024)} MB). "
                "Remove old imports or set ARKANA_MAX_IMPORT_DIR_SIZE_MB to change this limit."
            )
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

    # Extract artifact files
    if artifact_files:
        artifacts_dir = IMPORT_DIR / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        extracted_artifacts = 0
        for art_basename, art_data in artifact_files.items():
            art_dest = artifacts_dir / art_basename
            art_dest.write_bytes(art_data)
            extracted_artifacts += 1

        # Update artifact metadata paths using dedup name map
        wrapper_artifacts = wrapper.get("artifacts", [])
        for art_meta in wrapper_artifacts:
            old_basename = os.path.basename(art_meta.get("path", ""))
            deduped = artifact_name_map.get(old_basename, old_basename)
            if deduped and deduped in artifact_files:
                art_meta["path"] = str(artifacts_dir / deduped)
        wrapper["artifacts"] = wrapper_artifacts

        # Re-write the updated wrapper to cache
        if sha256 and len(sha256) == 64:
            cache_entry_path = CACHE_DIR / sha256[:2] / f"{sha256}.json.gz"
            if cache_entry_path.exists():
                with gzip.open(cache_entry_path, "wt", encoding="utf-8") as f:
                    json.dump(wrapper, f)

        result["artifacts_extracted"] = extracted_artifacts
        result["artifacts_dir"] = str(artifacts_dir)
        await ctx.info(f"Extracted {extracted_artifacts} artifact(s) to: {artifacts_dir}")

    return result
