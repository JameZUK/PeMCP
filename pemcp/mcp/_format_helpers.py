"""Shared helpers for binary format analysis tools."""
import os
from typing import Optional
from pemcp.config import state


def _check_lib(lib_name: str, available: bool, tool_name: str, pip_name: str = None):
    """Raise RuntimeError if a required library is not installed."""
    if not available:
        pkg = pip_name or lib_name
        raise RuntimeError(
            f"[{tool_name}] The '{lib_name}' library is not installed. "
            f"Install with: pip install {pkg}"
        )


def _get_filepath(file_path: Optional[str] = None) -> str:
    """Get the file path to analyze, defaulting to the loaded file."""
    target = file_path or state.filepath
    if not target or not os.path.isfile(target):
        raise RuntimeError("No file specified and no file is loaded. Use open_file() first.")
    if file_path is not None:
        state.check_path_allowed(os.path.realpath(target))
    return target
