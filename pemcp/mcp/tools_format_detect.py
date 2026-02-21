"""MCP tool for auto-detecting binary format from magic bytes."""
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
from pemcp.mcp._format_helpers import _get_filepath, _MACHO_MAGICS, _MACHO_FAT_MAGICS


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

        # ELF
        if header[:4] == b'\x7fELF':
            formats.append("ELF")
            bits = "64-bit" if header[4] == 2 else "32-bit"
            endian = "little-endian" if header[5] == 1 else "big-endian"
            result["elf_info"] = {"bits": bits, "endianness": endian}
            suggested_tools.extend(["elf_analyze", "elf_dwarf_info"])

        # Mach-O
        elif header[:4] in _MACHO_MAGICS:
            formats.append("Mach-O")
            is_64 = header[:4] in (b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe')
            result["macho_info"] = {"bits": "64-bit" if is_64 else "32-bit"}
            suggested_tools.extend(["macho_analyze"])

        # Mach-O Fat/Universal
        elif header[:4] in _MACHO_FAT_MAGICS:
            # 0xCAFEBABE is shared between Mach-O Fat and Java class files
            # Java class files have minor_version at offset 4 and major_version at offset 6
            # with major_version typically 45-65 (Java 1.1 to Java 21)
            if len(header) >= 8:
                major_ver = struct.unpack_from('>H', header, 6)[0]
                if 44 <= major_ver <= 68:
                    formats.append("Java Class File (or Mach-O Fat)")
                else:
                    formats.append("Mach-O Fat/Universal")
            else:
                formats.append("Mach-O Fat/Universal")
            suggested_tools.extend(["macho_analyze"])

        # PE
        elif header[:2] == b'MZ':
            formats.append("PE")
            suggested_tools.extend(["open_file", "get_triage_report"])

            # Check for .NET
            try:
                pe_offset = struct.unpack_from('<I', header, 0x3C)[0]
                if pe_offset + 4 < len(header) and header[pe_offset:pe_offset+4] == b'PE\x00\x00':
                    # Check for COM descriptor (data directory index 14)
                    oh_offset = pe_offset + 24
                    # Optional header magic
                    oh_magic = struct.unpack_from('<H', header, oh_offset)[0]
                    if oh_magic == 0x10b:  # PE32
                        com_desc_rva_offset = oh_offset + 208  # 14th data dir
                    elif oh_magic == 0x20b:  # PE32+
                        com_desc_rva_offset = oh_offset + 224
                    else:
                        com_desc_rva_offset = None

                    if com_desc_rva_offset and com_desc_rva_offset + 8 <= len(header):
                        com_rva = struct.unpack_from('<I', header, com_desc_rva_offset)[0]
                        if com_rva > 0:
                            formats.append(".NET")
                            suggested_tools.extend(["dotnet_analyze", "dotnet_disassemble_method"])
            except Exception:
                pass

        else:
            formats.append("Unknown")

        # Check for Go signatures (scan full scan_data, not just header)
        _go_markers = (b'Go build', b'go.buildid', b'runtime.main',
                       b'runtime.goexit', b'go.string.')
        if any(marker in scan_data for marker in _go_markers):
            formats.append("Go")
            suggested_tools.extend(["go_analyze"])

        # Check for Rust signatures (scan full scan_data for deeper markers)
        _rust_markers = (b'rustc/', b'.rustc', b'rust_begin_unwind',
                         b'rust_panic', b'core::panicking',
                         b'core::result::Result', b'alloc::string::String',
                         b'std::rt::lang_start', b'rust_eh_personality',
                         b'__rust_alloc', b'__rust_dealloc')
        if any(marker in scan_data for marker in _rust_markers):
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
