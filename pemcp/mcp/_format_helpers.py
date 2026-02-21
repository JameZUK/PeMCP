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
    if not target:
        raise RuntimeError("No file specified and no file is loaded. Use open_file() first.")
    if file_path is not None:
        state.check_path_allowed(os.path.realpath(target))
    if not os.path.isfile(target):
        raise RuntimeError(f"File not found: {target}")
    return target


# ── Magic-byte format detection ──────────────────────────────────────────

# Mach-O magic values (32/64 bit, big/little-endian, plus fat/universal)
_MACHO_MAGICS = (
    b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
    b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',
)
_MACHO_FAT_MAGICS = (
    b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
)


def detect_format_from_magic(magic: bytes) -> str:
    """Return a short format string from the first 4 bytes of a file.

    Returns one of: ``'pe'``, ``'elf'``, ``'macho'``, or ``'unknown'``.
    """
    if len(magic) < 2:
        return "unknown"
    if magic[:2] == b'MZ':
        return "pe"
    if magic[:4] == b'\x7fELF':
        return "elf"
    if magic[:4] in _MACHO_MAGICS or magic[:4] in _MACHO_FAT_MAGICS:
        return "macho"
    return "unknown"


def get_magic_hint(file_path: str) -> str:
    """Read the first 4 bytes of *file_path* and return a human-readable format hint.

    This is the canonical implementation used by ``list_samples`` and anywhere
    else that needs a quick format label.  Extended formats (ZIP, GZIP, etc.)
    are included beyond the core PE/ELF/Mach-O set.
    """
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)
    except Exception:
        return "Unreadable"

    fmt = detect_format_from_magic(magic)
    if fmt == "pe":
        return "PE"
    if fmt == "elf":
        return "ELF"
    if fmt == "macho":
        return "Mach-O"

    # Extended hints
    if magic[:2] == b'PK':
        return "ZIP/Archive"
    if magic[:3] == b'\x1f\x8b\x08':
        return "GZIP"
    if magic == b'\x7fCGC':
        return "CGC"
    if len(magic) >= 2 and magic[:2] == b'\xd0\xcf':
        return "OLE/MS-CFB"
    if magic[:4] == b'%PDF':
        return "PDF"
    return "Unknown"
