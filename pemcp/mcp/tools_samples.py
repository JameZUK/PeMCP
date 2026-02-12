"""MCP tool for listing and discovering sample files in the configured samples directory."""
import os
from typing import Dict, Any, Optional, List
from pathlib import Path

from pemcp.config import state, Context
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size


def _get_magic_hint(file_path: str) -> str:
    """Read the first 4 bytes and return a format hint."""
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)
        if magic[:2] == b'MZ':
            return "PE"
        elif magic == b'\x7fELF':
            return "ELF"
        elif magic in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                       b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',
                       b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
            return "Mach-O"
        elif magic[:2] == b'PK':
            return "ZIP/Archive"
        elif magic[:3] == b'\x1f\x8b\x08':
            return "GZIP"
        elif magic == b'\x7fCGC':
            return "CGC"
        elif len(magic) >= 2 and magic[:2] == b'\xd0\xcf':
            return "OLE/MS-CFB"
        elif magic[:4] == b'%PDF':
            return "PDF"
        return "Unknown"
    except Exception:
        return "Unreadable"


def _build_file_entry(file_path: str, base_path: str) -> Dict[str, Any]:
    """Build a metadata dict for a single file."""
    stat = os.stat(file_path)
    return {
        "name": os.path.basename(file_path),
        "path": file_path,
        "relative_path": os.path.relpath(file_path, base_path),
        "size_bytes": stat.st_size,
        "format_hint": _get_magic_hint(file_path),
    }


@tool_decorator
async def list_samples(
    ctx: Context,
    recursive: bool = False,
    glob_pattern: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Lists files available in the configured samples directory.
    Use this tool to discover what sample files are available for analysis
    before calling open_file. This tool does not require a file to be loaded.

    The samples directory is configured at server startup via --samples-path
    or the PEMCP_SAMPLES environment variable.

    Args:
        ctx: The MCP Context object.
        recursive: (bool) If True, list files in all subdirectories recursively.
                   If False (default), list only files in the top-level samples directory.
        glob_pattern: (Optional[str]) A glob pattern to filter files (e.g. '*.exe', '*.dll', 'malware_*').
                      Applied to filenames only (not full paths). If not set, all files are listed.

    Returns:
        A dictionary containing the samples directory path, file count,
        and a list of files with name, full path, relative path, size, and format hint.
    """
    if state.samples_path is None:
        return {
            "error": "No samples directory configured.",
            "hint": "Start the server with --samples-path <dir> or set the PEMCP_SAMPLES environment variable.",
        }

    samples_dir = state.samples_path

    if not os.path.isdir(samples_dir):
        return {
            "error": f"Configured samples directory does not exist: {samples_dir}",
            "hint": "Check the --samples-path value or PEMCP_SAMPLES environment variable.",
        }

    await ctx.info(f"Listing samples in: {samples_dir} (recursive={recursive})")

    files: List[Dict[str, Any]] = []

    if recursive:
        for root, dirs, filenames in os.walk(samples_dir):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for filename in filenames:
                if filename.startswith('.'):
                    continue
                if glob_pattern and not Path(filename).match(glob_pattern):
                    continue
                full_path = os.path.join(root, filename)
                try:
                    files.append(_build_file_entry(full_path, samples_dir))
                except (OSError, ValueError):
                    # Skip broken symlinks, permission errors, etc.
                    continue
    else:
        for entry in os.scandir(samples_dir):
            if not entry.is_file() or entry.name.startswith('.'):
                continue
            if glob_pattern and not Path(entry.name).match(glob_pattern):
                continue
            files.append(_build_file_entry(entry.path, samples_dir))

    # Sort by name for consistent output
    files.sort(key=lambda f: f["relative_path"])

    # Build directory tree summary for recursive listings
    subdirs: List[str] = []
    if recursive:
        seen = set()
        for f in files:
            rel = f["relative_path"]
            parts = Path(rel).parts
            if len(parts) > 1:
                subdir = str(Path(*parts[:-1]))
                if subdir not in seen:
                    seen.add(subdir)
                    subdirs.append(subdir)
        subdirs.sort()

    result: Dict[str, Any] = {
        "samples_path": samples_dir,
        "recursive": recursive,
        "total_files": len(files),
        "files": files,
    }

    if glob_pattern:
        result["glob_pattern"] = glob_pattern

    if subdirs:
        result["subdirectories"] = subdirs

    return await _check_mcp_response_size(ctx, result, "list_samples")
