"""Shared helpers for binary format analysis tools."""
import os
from typing import Optional
from arkana.config import state


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
    # Always validate path — even for state.filepath (defense-in-depth)
    resolved = os.path.realpath(target)
    state.check_path_allowed(resolved)
    if not os.path.isfile(resolved):
        raise RuntimeError(f"File not found: {target}")
    return resolved


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
    if magic[:4] == b'MDMP':
        return "Minidump"
    if magic[:4] == b'Rar!':
        return "RAR"
    if magic[:4] == b'7z\xbc\xaf':
        return "7-Zip"
    if magic[:4] == b'\xfd7zX':
        return "XZ"
    if magic[:4] in (b'dex\n', b'dey\n'):
        return "DEX" if magic[:4] == b'dex\n' else "ODEX"
    if magic[:4] in (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1'):
        return "PCAP"
    return "Unknown"


_FORMAT_LABELS = {"pe": "PE Executable", "elf": "ELF Binary", "macho": "Mach-O Binary"}

# ── Extended format detection ──────────────────────────────────────────────

# 2-byte prefix signatures (checked after 4-byte)
_EXTENDED_SIGNATURES_2 = {
    b'PK': ("zip", "ZIP/Archive"),
    b'\x1f\x8b': ("gzip", "GZIP Compressed"),
    b'\xd0\xcf': ("ole", "OLE/MS-CFB (Office)"),
    b'\x7fC': ("cgc", "CGC Binary"),       # \x7fCGC
    b'\xfd7': ("xz", "XZ Compressed"),
    b'de': ("dex", "Android DEX/ODEX"),     # dex\n or dey\n
}

# 4-byte signatures (checked first — more specific, fewer false positives)
_EXTENDED_SIGNATURES_4 = {
    b'\xa1\xb2\xc3\xd4': ("pcap", "PCAP Capture"),
    b'\xd4\xc3\xb2\xa1': ("pcap", "PCAP Capture (swapped)"),
    b'MDMP': ("minidump", "Windows Minidump"),
    b'Rar!': ("rar", "RAR Archive"),
    b'%PDF': ("pdf", "PDF Document"),
    b'dex\n': ("dex", "Android DEX"),
    b'dey\n': ("odex", "Android ODEX"),
    b'7z\xbc\xaf': ("7z", "7-Zip Archive"),
}


def detect_format_extended(magic: bytes) -> dict:
    """Return extended format info from the first 4 bytes.

    First checks binary formats via detect_format_from_magic(), then
    tries extended signatures for non-binary file types.

    Returns:
        {"code": str, "label": str}  e.g. {"code": "pdf", "label": "PDF Document"}
    """
    fmt = detect_format_from_magic(magic)
    if fmt != "unknown":
        return {"code": fmt, "label": _FORMAT_LABELS.get(fmt, fmt.upper())}

    # Try 4-byte exact matches first
    if len(magic) >= 4:
        match = _EXTENDED_SIGNATURES_4.get(magic[:4])
        if match:
            return {"code": match[0], "label": match[1]}

    # Try 2-byte prefix matches
    if len(magic) >= 2:
        match = _EXTENDED_SIGNATURES_2.get(magic[:2])
        if match:
            return {"code": match[0], "label": match[1]}

    return {"code": "unknown", "label": "Unknown"}
