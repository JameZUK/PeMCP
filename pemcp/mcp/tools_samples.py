"""MCP tool for listing and discovering sample files in the configured samples directory."""
import datetime
import os
from typing import Dict, Any, Optional, List
from pathlib import Path

from pemcp.config import state, Context
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size
from pemcp.mcp._format_helpers import get_magic_hint


# Mapping from get_magic_hint() return values to filter categories.
# Keys must match exact return values from get_magic_hint().
_FORMAT_CATEGORIES: Dict[str, str] = {
    "PE": "pe",
    "ELF": "elf",
    "Mach-O": "macho",
    "CGC": "binary",
    "ZIP/Archive": "archive",
    "GZIP": "archive",
    "OLE/MS-CFB": "document",
    "PDF": "document",
}

# Formats shown by default (analyzable binaries). Everything else requires show_all=True.
_ANALYZABLE_FORMATS = {"PE", "ELF", "Mach-O", "CGC"}


def _format_size(size_bytes: int) -> str:
    """Convert bytes to human-readable size string."""
    if size_bytes >= 1_048_576:
        return f"{size_bytes / 1_048_576:.1f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


def _build_file_entry(file_path: str, base_path: str) -> Dict[str, Any]:
    """Build a metadata dict for a single file."""
    stat = os.stat(file_path)
    mtime = datetime.datetime.fromtimestamp(
        stat.st_mtime, tz=datetime.timezone.utc
    ).strftime("%Y-%m-%d %H:%M UTC")
    return {
        "name": os.path.basename(file_path),
        "path": file_path,
        "relative_path": os.path.relpath(file_path, base_path),
        "size_bytes": stat.st_size,
        "size_human": _format_size(stat.st_size),
        "modified": mtime,
        "format_hint": get_magic_hint(file_path),
    }


@tool_decorator
async def list_samples(
    ctx: Context,
    recursive: bool = False,
    glob_pattern: Optional[str] = None,
    format_filter: str = "all",
    show_all: bool = False,
    sort_by: str = "name",
) -> Dict[str, Any]:
    """
    [Phase: load] Lists files available in the configured samples directory.
    Use this to discover what samples are available before calling open_file().

    By default, only analyzable binary formats (PE, ELF, Mach-O) are shown.
    PDFs, ZIPs, and other non-binary formats are hidden unless show_all=True.

    When to use: At the start of a session to see what files are available,
    or when the user asks which samples can be analyzed.

    The samples directory is configured at server startup via --samples-path
    or the PEMCP_SAMPLES environment variable.

    Next steps: open_file(file_path) to load a sample for analysis.

    Args:
        ctx: The MCP Context object.
        recursive: (bool) If True, list files in all subdirectories recursively.
                   If False (default), list only files in the top-level samples directory.
        glob_pattern: (Optional[str]) A glob pattern to filter files (e.g. '*.exe', '*.dll', 'malware_*').
                      Applied to filenames only (not full paths). If not set, all files are listed.
        format_filter: (str) Filter by detected format: 'pe', 'elf', 'macho', 'archive',
                       'document', 'binary', or 'all' (default). Based on magic-byte detection.
        show_all: (bool) If False (default), only shows analyzable binary formats
                  (PE, ELF, Mach-O). Set to True to include all files (PDFs, ZIPs, etc.).
        sort_by: (str) Sort results by: 'name' (default), 'size', or 'date'.

    Returns:
        A dictionary containing the samples directory path, file count,
        and a list of files with name, full path, relative path, size, human-readable size,
        modification date, and format hint.
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
            try:
                files.append(_build_file_entry(entry.path, samples_dir))
            except (OSError, ValueError):
                continue

    # --- Format filtering ---
    format_filter_lower = format_filter.lower()
    if format_filter_lower != "all":
        files = [
            f for f in files
            if _FORMAT_CATEGORIES.get(f.get("format_hint", ""), "") == format_filter_lower
        ]
    elif not show_all:
        # Default: only show analyzable binary formats (PE, ELF, Mach-O, CGC)
        files = [
            f for f in files
            if f.get("format_hint", "Unknown") in _ANALYZABLE_FORMATS
        ]

    # --- Sorting ---
    sort_by_lower = sort_by.lower()
    if sort_by_lower == "size":
        files.sort(key=lambda f: f.get("size_bytes", 0), reverse=True)
    elif sort_by_lower == "date":
        files.sort(key=lambda f: f.get("modified", ""), reverse=True)
    else:
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

    if format_filter_lower != "all":
        result["format_filter"] = format_filter_lower

    if show_all:
        result["show_all"] = True

    if sort_by_lower != "name":
        result["sort_by"] = sort_by_lower

    if subdirs:
        result["subdirectories"] = subdirs

    return await _check_mcp_response_size(ctx, result, "list_samples")
