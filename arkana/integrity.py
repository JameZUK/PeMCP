"""Pre-parse file integrity checks for binary formats.

Pure-Python module — uses only struct and collections (plus shannon_entropy
from arkana.utils).  No optional library dependencies.

Runs on raw bytes before handing data to pefile / pyelftools / LIEF, so it
can detect truncation, null-padding, impossible sizes, and header corruption
without risking hangs or crashes in those parsers.

Performance target: sub-100ms on 256 MB files.  Entropy and null-ratio are
computed on the first INTEGRITY_SAMPLE_SIZE bytes only.  All header checks
are O(1) struct unpacks.  Section iteration is bounded by constant caps.
"""
import logging
import struct
from typing import Dict, Any, List, Tuple

from arkana.constants import (
    INTEGRITY_NULL_RATIO_SUSPICIOUS,
    INTEGRITY_NULL_RATIO_CORRUPT,
    INTEGRITY_MIN_FILE_SIZE,
    INTEGRITY_PE_MIN_SIZE,
    INTEGRITY_ELF_MIN_SIZE,
    INTEGRITY_MACHO_MIN_SIZE,
    INTEGRITY_ENTROPY_PACKED,
    INTEGRITY_ENTROPY_NEAR_ZERO,
    INTEGRITY_MAX_SECTIONS_PE,
    INTEGRITY_SAMPLE_SIZE,
    INTEGRITY_MAX_ISSUES,
)
from arkana.utils import shannon_entropy

logger = logging.getLogger(__name__)

# ── Severity ordering (for classification) ─────────────────────────────────
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _issue(severity: str, code: str, message: str) -> Dict[str, str]:
    return {"severity": severity, "code": code, "message": message}


# ── Flag defaults ──────────────────────────────────────────────────────────
def _empty_flags() -> Dict[str, bool]:
    return {
        "truncated": False,
        "null_padded": False,
        "high_entropy": False,
        "impossible_sizes": False,
        "header_corrupt": False,
        "sections_oob": False,
    }


# ── Generic checks (all formats) ──────────────────────────────────────────
def _check_generic(
    data: bytes,
) -> Tuple[List[Dict[str, str]], Dict[str, bool], float, float]:
    """Check file-level properties: size, null ratio, entropy.

    Returns (issues, flags, entropy, null_ratio).
    """
    issues: List[Dict[str, str]] = []
    flags = _empty_flags()
    length = len(data)

    if length == 0:
        issues.append(_issue("critical", "FILE_EMPTY", "File is empty (0 bytes)."))
        return issues, flags, 0.0, 1.0

    # Sample first N bytes for entropy / null-ratio (fast on huge files)
    sample = data[: INTEGRITY_SAMPLE_SIZE]
    ent = shannon_entropy(sample)
    null_count = sample.count(b'\x00'[0])
    null_ratio = null_count / len(sample)

    if length < INTEGRITY_MIN_FILE_SIZE:
        issues.append(
            _issue(
                "medium",
                "FILE_TOO_SMALL",
                f"File is very small ({length} bytes), likely truncated or invalid.",
            )
        )

    if null_ratio >= INTEGRITY_NULL_RATIO_CORRUPT:
        issues.append(
            _issue(
                "high",
                "NULL_NEAR_TOTAL",
                f"File is {null_ratio:.1%} null bytes — almost certainly corrupt or zeroed.",
            )
        )
        flags["null_padded"] = True
    elif null_ratio >= INTEGRITY_NULL_RATIO_SUSPICIOUS:
        issues.append(
            _issue(
                "medium",
                "NULL_DOMINATED",
                f"File is {null_ratio:.1%} null bytes — likely null-padded or mostly empty.",
            )
        )
        flags["null_padded"] = True

    if ent >= INTEGRITY_ENTROPY_PACKED:
        issues.append(
            _issue(
                "info",
                "HIGH_ENTROPY",
                f"High entropy ({ent:.2f}/8.0) — may be packed, encrypted, or compressed.",
            )
        )
        flags["high_entropy"] = True
    elif ent < INTEGRITY_ENTROPY_NEAR_ZERO and length > INTEGRITY_MIN_FILE_SIZE:
        issues.append(
            _issue(
                "medium",
                "NEAR_ZERO_ENTROPY",
                f"Very low entropy ({ent:.2f}/8.0) — file may be mostly uniform data.",
            )
        )

    return issues, flags, ent, null_ratio


# ── PE integrity checks ───────────────────────────────────────────────────
def _check_pe_integrity(
    data: bytes,
) -> Tuple[List[Dict[str, str]], Dict[str, bool], Dict[str, Any]]:
    """Validate PE headers via struct unpacks. Returns (issues, flags, format_details)."""
    issues: List[Dict[str, str]] = []
    flags = _empty_flags()
    details: Dict[str, Any] = {}
    length = len(data)

    if length < 2 or data[:2] != b'MZ':
        issues.append(
            _issue("critical", "PE_DOS_MAGIC_MISSING", "Missing DOS magic (MZ). Not a valid PE.")
        )
        flags["header_corrupt"] = True
        return issues, flags, details

    if length < INTEGRITY_PE_MIN_SIZE:
        issues.append(
            _issue(
                "high",
                "PE_COFF_TRUNCATED",
                f"File too small for a valid PE ({length} bytes, minimum ~{INTEGRITY_PE_MIN_SIZE}).",
            )
        )
        flags["truncated"] = True
        return issues, flags, details

    # e_lfanew (offset to PE signature) at DOS header offset 0x3C
    if length < 0x40:
        issues.append(
            _issue("high", "PE_COFF_TRUNCATED", "DOS header truncated before e_lfanew field.")
        )
        flags["truncated"] = True
        return issues, flags, details

    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)

    if e_lfanew == 0 or e_lfanew > length - 4:
        issues.append(
            _issue(
                "critical",
                "PE_LFANEW_OOB",
                f"e_lfanew ({e_lfanew:#x}) is out of bounds (file size: {length}).",
            )
        )
        flags["header_corrupt"] = True
        return issues, flags, details

    # PE signature ("PE\0\0")
    pe_sig = data[e_lfanew : e_lfanew + 4]
    if pe_sig != b'PE\x00\x00':
        if len(pe_sig) < 4:
            issues.append(
                _issue(
                    "critical",
                    "PE_SIGNATURE_MISSING",
                    "File truncated before PE signature.",
                )
            )
            flags["truncated"] = True
        else:
            issues.append(
                _issue(
                    "high",
                    "PE_SIGNATURE_CORRUPT",
                    f"PE signature corrupt: expected 'PE\\0\\0', got {pe_sig.hex()}.",
                )
            )
            flags["header_corrupt"] = True
        return issues, flags, details

    # COFF header (20 bytes after PE sig)
    coff_offset = e_lfanew + 4
    if length < coff_offset + 20:
        issues.append(
            _issue("high", "PE_COFF_TRUNCATED", "COFF header truncated.")
        )
        flags["truncated"] = True
        return issues, flags, details

    machine, num_sections = struct.unpack_from("<HH", data, coff_offset)
    # Skip TimeDateStamp, PointerToSymbolTable, NumberOfSymbols
    (size_of_optional,) = struct.unpack_from("<H", data, coff_offset + 16)
    details["machine"] = f"{machine:#06x}"
    details["num_sections"] = num_sections

    # Known machine types
    _KNOWN_MACHINES = {
        0x0, 0x14C, 0x166, 0x169, 0x1A2, 0x1A3, 0x1A6, 0x1A8,
        0x1C0, 0x1C2, 0x1C4, 0x1D3, 0x200, 0x266, 0x284, 0x366,
        0x466, 0x5032, 0x5064, 0x8664, 0x9041, 0xAA64, 0xC0EE,
    }
    if machine not in _KNOWN_MACHINES:
        issues.append(
            _issue(
                "low",
                "PE_UNKNOWN_MACHINE",
                f"Unknown COFF machine type: {machine:#06x}.",
            )
        )

    if num_sections == 0:
        issues.append(
            _issue("low", "PE_ZERO_SECTIONS", "PE has zero sections.")
        )
    elif num_sections > INTEGRITY_MAX_SECTIONS_PE:
        issues.append(
            _issue(
                "medium",
                "PE_TOO_MANY_SECTIONS",
                f"PE has {num_sections} sections (max expected: {INTEGRITY_MAX_SECTIONS_PE}).",
            )
        )

    # Optional header
    opt_offset = coff_offset + 20
    if size_of_optional > 0 and length >= opt_offset + 2:
        (opt_magic,) = struct.unpack_from("<H", data, opt_offset)
        if opt_magic == 0x10B:
            details["pe_type"] = "PE32"
            # SizeOfImage at opt+56, SizeOfHeaders at opt+60, EntryPoint at opt+16
            if length >= opt_offset + 64:
                (entry_point,) = struct.unpack_from("<I", data, opt_offset + 16)
                (image_size,) = struct.unpack_from("<I", data, opt_offset + 56)
                (header_size,) = struct.unpack_from("<I", data, opt_offset + 60)
                details["image_size"] = image_size
                details["entry_point"] = f"{entry_point:#x}"
                if image_size == 0:
                    issues.append(
                        _issue("low", "PE_IMAGE_SIZE_ZERO", "SizeOfImage is zero.")
                    )
                if entry_point == 0:
                    issues.append(
                        _issue("low", "PE_ENTRY_POINT_ZERO", "AddressOfEntryPoint is zero (DLL or resource-only).")
                    )
                if header_size > length:
                    issues.append(
                        _issue(
                            "high",
                            "PE_HEADER_OOB",
                            f"SizeOfHeaders ({header_size}) exceeds file size ({length}).",
                        )
                    )
                    flags["impossible_sizes"] = True
        elif opt_magic == 0x20B:
            details["pe_type"] = "PE32+"
            # PE32+ layout: EntryPoint at opt+16, SizeOfImage at opt+56, SizeOfHeaders at opt+60
            if length >= opt_offset + 64:
                (entry_point,) = struct.unpack_from("<I", data, opt_offset + 16)
                (image_size,) = struct.unpack_from("<I", data, opt_offset + 56)
                (header_size,) = struct.unpack_from("<I", data, opt_offset + 60)
                details["image_size"] = image_size
                details["entry_point"] = f"{entry_point:#x}"
                if image_size == 0:
                    issues.append(
                        _issue("low", "PE_IMAGE_SIZE_ZERO", "SizeOfImage is zero.")
                    )
                if entry_point == 0:
                    issues.append(
                        _issue("low", "PE_ENTRY_POINT_ZERO", "AddressOfEntryPoint is zero (DLL or resource-only).")
                    )
                if header_size > length:
                    issues.append(
                        _issue(
                            "high",
                            "PE_HEADER_OOB",
                            f"SizeOfHeaders ({header_size}) exceeds file size ({length}).",
                        )
                    )
                    flags["impossible_sizes"] = True
        elif opt_magic == 0x107:
            details["pe_type"] = "ROM"
        else:
            details["pe_type"] = f"unknown ({opt_magic:#06x})"
            issues.append(
                _issue(
                    "medium",
                    "PE_OPTIONAL_MAGIC_UNKNOWN",
                    f"Unknown optional header magic: {opt_magic:#06x}.",
                )
            )

    # Section table validation
    section_table_offset = opt_offset + size_of_optional
    _SECTION_ENTRY_SIZE = 40
    sections_checked = min(num_sections, INTEGRITY_MAX_SECTIONS_PE)
    for i in range(sections_checked):
        sec_off = section_table_offset + i * _SECTION_ENTRY_SIZE
        if sec_off + _SECTION_ENTRY_SIZE > length:
            issues.append(
                _issue(
                    "high",
                    "PE_COFF_TRUNCATED",
                    f"Section table truncated at section {i} (offset {sec_off:#x}).",
                )
            )
            flags["truncated"] = True
            break
        # PointerToRawData at +20, SizeOfRawData at +16
        raw_size, raw_ptr = struct.unpack_from("<II", data, sec_off + 16)
        if raw_ptr > 0 and raw_size > 0 and raw_ptr + raw_size > length:
            issues.append(
                _issue(
                    "medium",
                    "PE_SECTION_OOB",
                    f"Section {i}: raw data ({raw_ptr:#x}+{raw_size:#x}) exceeds file size ({length:#x}).",
                )
            )
            flags["sections_oob"] = True

    return issues, flags, details


# ── ELF integrity checks ──────────────────────────────────────────────────
def _check_elf_integrity(
    data: bytes,
) -> Tuple[List[Dict[str, str]], Dict[str, bool], Dict[str, Any]]:
    """Validate ELF headers. Returns (issues, flags, format_details)."""
    issues: List[Dict[str, str]] = []
    flags = _empty_flags()
    details: Dict[str, Any] = {}
    length = len(data)

    if length < 16:
        issues.append(
            _issue("high", "PE_COFF_TRUNCATED", "ELF header truncated (< 16 bytes).")
        )
        flags["truncated"] = True
        return issues, flags, details

    # EI_CLASS (offset 4): 1=32-bit, 2=64-bit
    ei_class = data[4]
    if ei_class not in (1, 2):
        issues.append(
            _issue(
                "critical",
                "ELF_CLASS_INVALID",
                f"Invalid EI_CLASS: {ei_class} (expected 1=32-bit or 2=64-bit).",
            )
        )
        flags["header_corrupt"] = True
        return issues, flags, details

    details["elf_class"] = "ELF32" if ei_class == 1 else "ELF64"

    # EI_DATA (offset 5): 1=LE, 2=BE
    ei_data = data[5]
    if ei_data not in (1, 2):
        issues.append(
            _issue(
                "critical",
                "ELF_DATA_INVALID",
                f"Invalid EI_DATA: {ei_data} (expected 1=LE or 2=BE).",
            )
        )
        flags["header_corrupt"] = True
        return issues, flags, details

    endian = "<" if ei_data == 1 else ">"
    details["endianness"] = "little" if ei_data == 1 else "big"

    # EI_VERSION (offset 6)
    ei_version = data[6]
    if ei_version != 1:
        issues.append(
            _issue(
                "low",
                "ELF_VERSION_INVALID",
                f"EI_VERSION is {ei_version} (expected 1).",
            )
        )

    min_hdr = INTEGRITY_ELF_MIN_SIZE if ei_class == 1 else 64
    if length < min_hdr:
        issues.append(
            _issue(
                "high",
                "PE_COFF_TRUNCATED",
                f"ELF header truncated ({length} bytes, need {min_hdr}).",
            )
        )
        flags["truncated"] = True
        return issues, flags, details

    if ei_class == 1:
        # 32-bit ELF header
        e_phoff, = struct.unpack_from(f"{endian}I", data, 28)
        e_shoff, = struct.unpack_from(f"{endian}I", data, 32)
        e_phentsize, = struct.unpack_from(f"{endian}H", data, 42)
        e_phnum, = struct.unpack_from(f"{endian}H", data, 44)
        e_shentsize, = struct.unpack_from(f"{endian}H", data, 46)
        e_shnum, = struct.unpack_from(f"{endian}H", data, 48)
    else:
        # 64-bit ELF header
        e_phoff, = struct.unpack_from(f"{endian}Q", data, 32)
        e_shoff, = struct.unpack_from(f"{endian}Q", data, 40)
        e_phentsize, = struct.unpack_from(f"{endian}H", data, 54)
        e_phnum, = struct.unpack_from(f"{endian}H", data, 56)
        e_shentsize, = struct.unpack_from(f"{endian}H", data, 58)
        e_shnum, = struct.unpack_from(f"{endian}H", data, 60)

    details["e_phnum"] = e_phnum
    details["e_shnum"] = e_shnum

    # Program header bounds
    if e_phnum > 0 and e_phoff > 0:
        # Standard phentsize for 32-bit is 32, for 64-bit is 56
        expected_phent = 32 if ei_class == 1 else 56
        if e_phentsize not in (0, expected_phent):
            issues.append(
                _issue(
                    "info",
                    "ELF_PHDR_SIZE_UNUSUAL",
                    f"Program header entry size is {e_phentsize} (expected {expected_phent}).",
                )
            )
        ph_end = e_phoff + e_phnum * (e_phentsize if e_phentsize > 0 else expected_phent)
        if ph_end > length:
            issues.append(
                _issue(
                    "high",
                    "ELF_PHDR_OOB",
                    f"Program headers ({e_phoff:#x}+{e_phnum}*{e_phentsize}) exceed file size ({length}).",
                )
            )
            flags["sections_oob"] = True

    # Section header bounds
    if e_shnum > 0 and e_shoff > 0:
        expected_shent = 40 if ei_class == 1 else 64
        if e_shentsize not in (0, expected_shent):
            issues.append(
                _issue(
                    "info",
                    "ELF_SHDR_SIZE_UNUSUAL",
                    f"Section header entry size is {e_shentsize} (expected {expected_shent}).",
                )
            )
        sh_end = e_shoff + e_shnum * (e_shentsize if e_shentsize > 0 else expected_shent)
        if sh_end > length:
            issues.append(
                _issue(
                    "high",
                    "ELF_SHDR_OOB",
                    f"Section headers ({e_shoff:#x}+{e_shnum}*{e_shentsize}) exceed file size ({length}).",
                )
            )
            flags["sections_oob"] = True

    return issues, flags, details


# ── Mach-O integrity checks ───────────────────────────────────────────────

_MACHO_MAGICS_LE = {0xFEEDFACE, 0xFEEDFACF}  # 32/64 little-endian on disk
_MACHO_MAGICS_BE = {0xCEFAEDFE, 0xCFFAEDFE}  # 32/64 big-endian on disk
_MACHO_FAT_MAGIC = {0xCAFEBABE, 0xBEBAFECA}


def _check_macho_integrity(
    data: bytes,
) -> Tuple[List[Dict[str, str]], Dict[str, bool], Dict[str, Any]]:
    """Validate Mach-O headers. Returns (issues, flags, format_details)."""
    issues: List[Dict[str, str]] = []
    flags = _empty_flags()
    details: Dict[str, Any] = {}
    length = len(data)

    if length < INTEGRITY_MACHO_MIN_SIZE:
        issues.append(
            _issue(
                "high",
                "MACHO_CMDS_OOB",
                f"File too small for a valid Mach-O ({length} bytes).",
            )
        )
        flags["truncated"] = True
        return issues, flags, details

    # Determine endianness from magic
    magic_le, = struct.unpack_from("<I", data, 0)
    magic_be, = struct.unpack_from(">I", data, 0)

    if magic_le in _MACHO_FAT_MAGIC:
        return _check_macho_fat(data, issues, flags, details)

    is_64 = False
    if magic_le == 0xFEEDFACF or magic_be == 0xFEEDFACF:
        endian = "<" if magic_le == 0xFEEDFACF else ">"
        is_64 = True
    elif magic_le == 0xFEEDFACE or magic_be == 0xFEEDFACE:
        endian = "<" if magic_le == 0xFEEDFACE else ">"
        is_64 = False
    else:
        endian = "<"

    details["macho_type"] = "Mach-O 64" if is_64 else "Mach-O 32"

    # Mach-O header: magic(4) + cputype(4) + cpusubtype(4) + filetype(4) + ncmds(4) + sizeofcmds(4)
    hdr_size = 32 if is_64 else 28
    if length < hdr_size:
        issues.append(
            _issue("high", "MACHO_CMDS_OOB", "Mach-O header truncated.")
        )
        flags["truncated"] = True
        return issues, flags, details

    filetype, = struct.unpack_from(f"{endian}I", data, 12)
    ncmds, = struct.unpack_from(f"{endian}I", data, 16)
    sizeofcmds, = struct.unpack_from(f"{endian}I", data, 20)

    details["filetype"] = filetype
    details["ncmds"] = ncmds
    details["sizeofcmds"] = sizeofcmds

    # Known filetypes: 1=OBJECT, 2=EXECUTE, 3=FVMLIB, 4=CORE, 5=PRELOAD,
    # 6=DYLIB, 7=DYLINKER, 8=BUNDLE, 9=DYLIB_STUB, 10=DSYM, 11=KEXT_BUNDLE, 12=FILESET
    if filetype > 12:
        issues.append(
            _issue(
                "low",
                "MACHO_UNKNOWN_FILETYPE",
                f"Unknown Mach-O filetype: {filetype}.",
            )
        )

    if ncmds == 0:
        issues.append(
            _issue("low", "MACHO_NCMDS_ZERO", "Mach-O has zero load commands.")
        )
        return issues, flags, details

    # Validate sizeofcmds doesn't exceed file
    cmds_start = hdr_size
    if cmds_start + sizeofcmds > length:
        issues.append(
            _issue(
                "high",
                "MACHO_CMDS_OOB",
                f"Load commands region ({cmds_start:#x}+{sizeofcmds:#x}) exceeds file size ({length}).",
            )
        )
        flags["sections_oob"] = True
        return issues, flags, details

    # Walk load commands
    offset = cmds_start
    # LC_SEGMENT=1, LC_SEGMENT_64=0x19
    _LC_SEGMENT = 1
    _LC_SEGMENT_64 = 0x19
    max_walk = min(ncmds, 256)  # cap iteration
    for i in range(max_walk):
        if offset + 8 > length:
            issues.append(
                _issue(
                    "high",
                    "MACHO_CMDS_OOB",
                    f"Load command {i} truncated at offset {offset:#x}.",
                )
            )
            flags["truncated"] = True
            break
        cmd, cmdsize = struct.unpack_from(f"{endian}II", data, offset)
        if cmdsize == 0:
            issues.append(
                _issue(
                    "high",
                    "MACHO_CMDSIZE_ZERO",
                    f"Load command {i} has cmdsize=0 (would cause infinite loop).",
                )
            )
            flags["header_corrupt"] = True
            break
        if offset + cmdsize > length:
            issues.append(
                _issue(
                    "high",
                    "MACHO_CMDS_OOB",
                    f"Load command {i} (cmd={cmd:#x}, size={cmdsize}) exceeds file bounds.",
                )
            )
            flags["sections_oob"] = True
            break

        # Check LC_SEGMENT / LC_SEGMENT_64 fileoff+filesize
        if cmd == _LC_SEGMENT and cmdsize >= 56:
            # 32-bit segment: fileoff at +32, filesize at +36
            fileoff, filesize = struct.unpack_from(f"{endian}II", data, offset + 32)
            if fileoff > 0 and filesize > 0 and fileoff + filesize > length:
                issues.append(
                    _issue(
                        "medium",
                        "MACHO_SEGMENT_OOB",
                        f"Segment {i}: file region ({fileoff:#x}+{filesize:#x}) exceeds file size.",
                    )
                )
                flags["sections_oob"] = True
        elif cmd == _LC_SEGMENT_64 and cmdsize >= 72:
            # 64-bit segment: fileoff at +40, filesize at +48
            fileoff, filesize = struct.unpack_from(f"{endian}QQ", data, offset + 40)
            if fileoff > 0 and filesize > 0 and fileoff + filesize > length:
                issues.append(
                    _issue(
                        "medium",
                        "MACHO_SEGMENT_OOB",
                        f"Segment {i}: file region ({fileoff:#x}+{filesize:#x}) exceeds file size.",
                    )
                )
                flags["sections_oob"] = True

        offset += cmdsize

    return issues, flags, details


def _check_macho_fat(
    data: bytes,
    issues: List[Dict[str, str]],
    flags: Dict[str, bool],
    details: Dict[str, Any],
) -> Tuple[List[Dict[str, str]], Dict[str, bool], Dict[str, Any]]:
    """Validate a Mach-O fat/universal binary header."""
    length = len(data)
    details["macho_type"] = "Fat/Universal"

    if length < 8:
        issues.append(
            _issue("high", "MACHO_CMDS_OOB", "Fat header truncated.")
        )
        flags["truncated"] = True
        return issues, flags, details

    # Fat header is always big-endian
    nfat_arch, = struct.unpack_from(">I", data, 4)
    details["nfat_arch"] = nfat_arch

    if nfat_arch == 0:
        issues.append(
            _issue("low", "MACHO_NCMDS_ZERO", "Fat binary has zero architectures.")
        )
        return issues, flags, details

    # Each fat_arch is 20 bytes, starting at offset 8
    max_check = min(nfat_arch, 32)
    for i in range(max_check):
        arch_off = 8 + i * 20
        if arch_off + 20 > length:
            issues.append(
                _issue(
                    "medium",
                    "MACHO_FAT_ARCH_OOB",
                    f"Fat arch entry {i} truncated.",
                )
            )
            flags["truncated"] = True
            break
        # offset(4) + size(4) at positions +8 and +12 within fat_arch
        f_offset, f_size = struct.unpack_from(">II", data, arch_off + 8)
        if f_offset + f_size > length:
            issues.append(
                _issue(
                    "medium",
                    "MACHO_FAT_ARCH_OOB",
                    f"Fat arch {i}: region ({f_offset:#x}+{f_size:#x}) exceeds file size.",
                )
            )
            flags["sections_oob"] = True

    return issues, flags, details


# ── Status classification ─────────────────────────────────────────────────
def _classify_status(
    issues: List[Dict[str, str]], flags: Dict[str, bool]
) -> Tuple[str, str]:
    """Derive (status, confidence) from issues list.

    Returns:
        status: "healthy", "suspicious", "partial", or "corrupt"
        confidence: "high", "medium", or "low"
    """
    if not issues:
        return "healthy", "high"

    worst = min(
        (issue["severity"] for issue in issues),
        key=lambda s: _SEVERITY_ORDER.get(s, 99),
    )

    if worst == "critical":
        return "corrupt", "high"
    if worst == "high":
        return "partial", "high"
    if worst == "medium":
        return "suspicious", "medium"
    # low or info only
    return "healthy", "high"


# ── Recommendation builder ────────────────────────────────────────────────
def _build_recommendation(
    status: str, detected_format: str, flags: Dict[str, bool]
) -> str:
    if status == "healthy":
        return "File appears healthy. Proceed with normal analysis."
    if status == "corrupt":
        parts = ["File appears corrupt."]
        if flags.get("header_corrupt"):
            parts.append("Header validation failed — parser may crash or produce garbage.")
        if flags.get("truncated"):
            parts.append("File is truncated — analysis will be incomplete.")
        parts.append("Use force=True to attempt loading anyway, or check_file_integrity for details.")
        return " ".join(parts)
    if status == "partial":
        parts = ["File has significant issues."]
        if flags.get("sections_oob"):
            parts.append("Some sections/segments extend beyond file bounds.")
        if flags.get("null_padded"):
            parts.append("File is mostly null bytes.")
        parts.append("Analysis may succeed but results could be incomplete. Using reduced timeout.")
        return " ".join(parts)
    # suspicious
    parts = ["File has minor issues."]
    if flags.get("high_entropy"):
        parts.append("High entropy suggests packing/encryption.")
    if flags.get("null_padded"):
        parts.append("High null-byte ratio.")
    parts.append("Analysis should work but verify results.")
    return " ".join(parts)


# ── Format label mapping ─────────────────────────────────────────────────
_FORMAT_LABELS = {
    "pe": "PE",
    "elf": "ELF",
    "macho": "Mach-O",
    "shellcode": "Shellcode/Raw",
    "unknown": "Unknown",
}


# ── Main public function ──────────────────────────────────────────────────
def check_file_integrity(
    data: bytes, detected_format: str, file_path: str = "<unknown>"
) -> Dict[str, Any]:
    """Run pre-parse integrity checks on raw binary data.

    Args:
        data: Raw file bytes.
        detected_format: One of "pe", "elf", "macho", "shellcode", "unknown".
        file_path: For logging only.

    Returns:
        Dict with keys: status, confidence, file_size, detected_format,
        format_label, entropy, null_ratio, issues, flags, format_details,
        recommendation.
    """
    # Generic checks
    generic_issues, generic_flags, entropy, null_ratio = _check_generic(data)

    # Format-specific checks
    fmt_issues: List[Dict[str, str]] = []
    fmt_flags: Dict[str, bool] = {}
    fmt_details: Dict[str, Any] = {}

    if detected_format == "pe":
        fmt_issues, fmt_flags, fmt_details = _check_pe_integrity(data)
    elif detected_format == "elf":
        fmt_issues, fmt_flags, fmt_details = _check_elf_integrity(data)
    elif detected_format == "macho":
        fmt_issues, fmt_flags, fmt_details = _check_macho_integrity(data)

    # Merge
    all_issues = (generic_issues + fmt_issues)[:INTEGRITY_MAX_ISSUES]
    merged_flags = {**generic_flags}
    for k, v in fmt_flags.items():
        if v:
            merged_flags[k] = True

    status, confidence = _classify_status(all_issues, merged_flags)
    recommendation = _build_recommendation(status, detected_format, merged_flags)

    return {
        "status": status,
        "confidence": confidence,
        "file_size": len(data),
        "detected_format": detected_format,
        "format_label": _FORMAT_LABELS.get(detected_format, "Unknown"),
        "entropy": round(entropy, 2),
        "null_ratio": round(null_ratio, 4),
        "issues": all_issues,
        "flags": merged_flags,
        "format_details": fmt_details,
        "recommendation": recommendation,
    }
