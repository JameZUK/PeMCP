"""MCP tool for auto-detecting binary format from magic bytes.

Uses the canonical ``detect_format_from_magic()`` helper from
``_format_helpers`` for basic PE/ELF/Mach-O classification, then adds
enhanced detection for .NET, Java class files, Go, and Rust.
"""
import struct
import asyncio
from typing import Dict, Any, Optional
from pemcp.config import (
    state, logger, Context,
    DNFILE_AVAILABLE, DNCIL_AVAILABLE, PYGORE_AVAILABLE,
    RUSTBININFO_AVAILABLE, RUST_DEMANGLER_AVAILABLE,
    PYELFTOOLS_AVAILABLE, LIEF_AVAILABLE,
)
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size
from pemcp.mcp._format_helpers import (
    _get_filepath, detect_format_from_magic, _MACHO_MAGICS, _MACHO_FAT_MAGICS,
)


def _check_dotnet(header: bytes) -> bool:
    """Return True if the PE header contains a non-zero COM descriptor RVA (.NET)."""
    try:
        pe_offset = struct.unpack_from('<I', header, 0x3C)[0]
        if pe_offset + 4 >= len(header) or header[pe_offset:pe_offset + 4] != b'PE\x00\x00':
            return False
        oh_offset = pe_offset + 24
        oh_magic = struct.unpack_from('<H', header, oh_offset)[0]
        if oh_magic == 0x10b:  # PE32
            com_desc_rva_offset = oh_offset + 208
        elif oh_magic == 0x20b:  # PE32+
            com_desc_rva_offset = oh_offset + 224
        else:
            return False
        if com_desc_rva_offset + 8 > len(header):
            return False
        return struct.unpack_from('<I', header, com_desc_rva_offset)[0] > 0
    except Exception:
        return False


# Language-specific byte markers for deep scanning
_GO_MARKERS = (b'Go build', b'go.buildid', b'runtime.main',
               b'runtime.goexit', b'go.string.')
_RUST_MARKERS = (b'rustc/', b'.rustc', b'rust_begin_unwind',
                 b'rust_panic', b'core::panicking',
                 b'core::result::Result', b'alloc::string::String',
                 b'std::rt::lang_start', b'rust_eh_personality',
                 b'__rust_alloc', b'__rust_dealloc')


@tool_decorator
async def detect_binary_format(
    ctx: Context,
    file_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Auto-detects binary format from magic bytes: PE, ELF, Mach-O, .NET, Go, Rust.
    Returns the format, suggested analysis tools, and basic metadata.

    Args:
        file_path: Optional path to a binary. If None, uses the loaded file.
    """
    await ctx.info("Detecting binary format")
    target = _get_filepath(file_path)

    def _detect():
        with open(target, 'rb') as f:
            header = f.read(4096)
            file_size = f.seek(0, 2)
            f.seek(0)
            # Read a larger chunk for language-specific marker scanning.
            # Rust and Go markers are often deep in the binary (string tables,
            # section data) rather than in the first few KB.
            scan_size = min(file_size, 2 * 1024 * 1024)  # up to 2MB
            f.seek(0)
            scan_data = f.read(scan_size)

        result: Dict[str, Any] = {"file": target, "size": file_size}
        formats = []
        suggested_tools = []

        # Use the canonical helper for basic format classification
        base_format = detect_format_from_magic(header[:4])

        if base_format == "elf":
            formats.append("ELF")
            bits = "64-bit" if len(header) > 4 and header[4] == 2 else "32-bit"
            endian = "little-endian" if len(header) > 5 and header[5] == 1 else "big-endian"
            result["elf_info"] = {"bits": bits, "endianness": endian}
            suggested_tools.extend(["elf_analyze", "elf_dwarf_info"])

        elif base_format == "macho":
            # Distinguish between regular Mach-O and Fat/Universal
            if header[:4] in _MACHO_FAT_MAGICS:
                # 0xCAFEBABE is shared with Java class files
                if len(header) >= 8:
                    major_ver = struct.unpack_from('>H', header, 6)[0]
                    if 44 <= major_ver <= 68:
                        formats.append("Java Class File (or Mach-O Fat)")
                    else:
                        formats.append("Mach-O Fat/Universal")
                else:
                    formats.append("Mach-O Fat/Universal")
            else:
                formats.append("Mach-O")
                is_64 = header[:4] in (b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe')
                result["macho_info"] = {"bits": "64-bit" if is_64 else "32-bit"}
            suggested_tools.extend(["macho_analyze"])

        elif base_format == "pe":
            formats.append("PE")
            suggested_tools.extend(["open_file", "get_triage_report"])
            if _check_dotnet(header):
                formats.append(".NET")
                suggested_tools.extend(["dotnet_analyze", "dotnet_disassemble_method"])

        else:
            formats.append("Unknown")

        # Check for Go signatures (scan full scan_data, not just header)
        if any(marker in scan_data for marker in _GO_MARKERS):
            formats.append("Go")
            suggested_tools.extend(["go_analyze"])

        # Check for Rust signatures (scan full scan_data for deeper markers)
        if any(marker in scan_data for marker in _RUST_MARKERS):
            formats.append("Rust")
            suggested_tools.extend(["rust_analyze", "rust_demangle_symbols"])

        result["detected_formats"] = formats
        result["primary_format"] = formats[0] if formats else "Unknown"
        result["suggested_tools"] = list(dict.fromkeys(suggested_tools))  # dedupe preserving order

        # Report available libraries
        result["library_support"] = {
            "dnfile": DNFILE_AVAILABLE,
            "dncil": DNCIL_AVAILABLE,
            "pygore": PYGORE_AVAILABLE,
            "rustbininfo": RUSTBININFO_AVAILABLE,
            "rust_demangler": RUST_DEMANGLER_AVAILABLE,
            "pyelftools": PYELFTOOLS_AVAILABLE,
            "lief": LIEF_AVAILABLE,
        }

        return result

    result = await asyncio.to_thread(_detect)
    return await _check_mcp_response_size(ctx, result, "detect_binary_format")
