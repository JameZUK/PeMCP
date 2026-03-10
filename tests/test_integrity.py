"""Unit tests for arkana.integrity — pre-parse file integrity checks."""
import struct
import pytest

from arkana.integrity import (
    check_file_integrity,
    _check_generic,
    _check_pe_integrity,
    _check_elf_integrity,
    _check_macho_integrity,
    _classify_status,
    _empty_flags,
    _issue,
)
from arkana.constants import (
    INTEGRITY_MAX_ISSUES,
    INTEGRITY_MAX_SECTIONS_PE,
)


# ── Helpers ────────────────────────────────────────────────────────────────

def _build_minimal_pe(
    num_sections: int = 1,
    *,
    machine: int = 0x14C,
    pe_magic: int = 0x10B,
    image_size: int = 0x1000,
    entry_point: int = 0x1000,
    extra_data: bytes = b"",
) -> bytearray:
    """Construct a minimal valid PE file via struct.pack_into."""
    e_lfanew = 0x80  # typical offset
    opt_header_size = 96 if pe_magic == 0x10B else 112  # minimal
    section_size = 40
    total = e_lfanew + 4 + 20 + opt_header_size + num_sections * section_size + 512
    buf = bytearray(b'\xCC' * total)  # fill with non-null to avoid NULL_DOMINATED

    # DOS header
    struct.pack_into("<2s", buf, 0, b"MZ")
    struct.pack_into("<I", buf, 0x3C, e_lfanew)

    # PE signature
    struct.pack_into("<4s", buf, e_lfanew, b"PE\x00\x00")

    # COFF header
    coff = e_lfanew + 4
    struct.pack_into("<HH", buf, coff, machine, num_sections)
    struct.pack_into("<H", buf, coff + 16, opt_header_size)  # SizeOfOptionalHeader

    # Optional header
    opt = coff + 20
    struct.pack_into("<H", buf, opt, pe_magic)
    struct.pack_into("<I", buf, opt + 16, entry_point)  # AddressOfEntryPoint
    header_size = e_lfanew + 4 + 20 + opt_header_size + num_sections * section_size
    struct.pack_into("<I", buf, opt + 56, image_size)  # SizeOfImage
    struct.pack_into("<I", buf, opt + 60, header_size)  # SizeOfHeaders

    # Section table — one valid section pointing inside file
    sec_start = opt + opt_header_size
    for i in range(num_sections):
        sec_off = sec_start + i * section_size
        name = f".sec{i}"[:8].encode().ljust(8, b'\x00')
        struct.pack_into("<8s", buf, sec_off, name)
        # VirtualSize, VirtualAddress
        struct.pack_into("<II", buf, sec_off + 8, 0x200, 0x1000 + i * 0x1000)
        # SizeOfRawData, PointerToRawData (point to safe area in file)
        struct.pack_into("<II", buf, sec_off + 16, 0x100, header_size + i * 0x100)

    if extra_data:
        buf.extend(extra_data)

    return buf


def _build_minimal_elf(
    bits: int = 64,
    endian: str = "little",
    *,
    e_phnum: int = 0,
    e_shnum: int = 0,
    e_phoff: int = 0,
    e_shoff: int = 0,
) -> bytearray:
    """Construct a minimal valid ELF header."""
    ei_class = 2 if bits == 64 else 1
    ei_data = 1 if endian == "little" else 2
    fmt = "<" if endian == "little" else ">"
    hdr_size = 64 if bits == 64 else 52

    buf = bytearray(b'\xCC' * max(hdr_size, 256))  # fill with non-null

    # ELF magic
    buf[0:4] = b'\x7fELF'
    buf[4] = ei_class
    buf[5] = ei_data
    buf[6] = 1  # EI_VERSION

    if bits == 64:
        # e_type, e_machine, e_version
        struct.pack_into(f"{fmt}HHI", buf, 16, 2, 0x3E, 1)  # ET_EXEC, EM_X86_64
        # e_entry (8 bytes)
        struct.pack_into(f"{fmt}Q", buf, 24, 0x400000)
        # e_phoff (8 bytes)
        struct.pack_into(f"{fmt}Q", buf, 32, e_phoff)
        # e_shoff (8 bytes)
        struct.pack_into(f"{fmt}Q", buf, 40, e_shoff)
        # e_flags (4), e_ehsize (2), e_phentsize (2), e_phnum (2), e_shentsize (2), e_shnum (2), e_shstrndx (2)
        struct.pack_into(f"{fmt}IHHHHHH", buf, 48, 0, hdr_size, 56, e_phnum, 64, e_shnum, 0)
    else:
        struct.pack_into(f"{fmt}HHI", buf, 16, 2, 3, 1)  # ET_EXEC, EM_386
        struct.pack_into(f"{fmt}I", buf, 24, 0x8048000)  # e_entry
        struct.pack_into(f"{fmt}I", buf, 28, e_phoff)
        struct.pack_into(f"{fmt}I", buf, 32, e_shoff)
        struct.pack_into(f"{fmt}IHHHHHH", buf, 36, 0, hdr_size, 32, e_phnum, 40, e_shnum, 0)

    return buf


def _build_minimal_macho_64(
    ncmds: int = 0,
    sizeofcmds: int = 0,
    filetype: int = 2,
) -> bytearray:
    """Construct a minimal valid 64-bit little-endian Mach-O header."""
    hdr_size = 32
    total = hdr_size + sizeofcmds + 64
    buf = bytearray(b'\xCC' * total)  # fill with non-null

    # Magic (64-bit LE)
    struct.pack_into("<I", buf, 0, 0xFEEDFACF)
    # cputype, cpusubtype
    struct.pack_into("<II", buf, 4, 0x01000007, 3)  # x86_64
    # filetype
    struct.pack_into("<I", buf, 12, filetype)
    # ncmds
    struct.pack_into("<I", buf, 16, ncmds)
    # sizeofcmds
    struct.pack_into("<I", buf, 20, sizeofcmds)

    return buf


def _has_code(issues, code):
    """Check if any issue has the given code."""
    return any(i["code"] == code for i in issues)


# ── TestCheckGeneric ──────────────────────────────────────────────────────

class TestCheckGeneric:
    def test_empty_file(self):
        issues, flags, ent, null_ratio = _check_generic(b"")
        assert _has_code(issues, "FILE_EMPTY")
        assert null_ratio == 1.0

    def test_tiny_file(self):
        issues, flags, ent, null_ratio = _check_generic(b"\x01\x02\x03")
        assert _has_code(issues, "FILE_TOO_SMALL")

    def test_null_dominated(self):
        # 96% null
        data = b"\x00" * 960 + b"\x41" * 40
        issues, flags, ent, null_ratio = _check_generic(data)
        assert _has_code(issues, "NULL_DOMINATED")
        assert flags["null_padded"]

    def test_null_near_total(self):
        # 99.5% null
        data = b"\x00" * 995 + b"\x41" * 5
        issues, flags, ent, null_ratio = _check_generic(data)
        assert _has_code(issues, "NULL_NEAR_TOTAL")
        assert flags["null_padded"]

    def test_high_entropy(self):
        import os
        data = os.urandom(4096)
        issues, flags, ent, null_ratio = _check_generic(data)
        assert _has_code(issues, "HIGH_ENTROPY")
        assert flags["high_entropy"]

    def test_normal_data(self):
        # Normal-ish data: mix of values, not too random, not too uniform
        data = bytes(range(256)) * 4  # 1024 bytes, moderate entropy
        issues, flags, ent, null_ratio = _check_generic(data)
        # Should have no critical/high issues
        for issue in issues:
            assert issue["severity"] not in ("critical", "high")

    def test_near_zero_entropy(self):
        # Data with very low entropy (all same byte, >64 bytes)
        data = b"\x42" * 200
        issues, flags, ent, null_ratio = _check_generic(data)
        assert _has_code(issues, "NEAR_ZERO_ENTROPY")

    def test_return_schema(self):
        issues, flags, ent, null_ratio = _check_generic(b"\x00" * 100)
        assert isinstance(issues, list)
        assert isinstance(flags, dict)
        assert isinstance(ent, float)
        assert isinstance(null_ratio, float)
        # All flag keys present
        for key in ("truncated", "null_padded", "high_entropy",
                     "impossible_sizes", "header_corrupt", "sections_oob"):
            assert key in flags


# ── TestPEIntegrity ───────────────────────────────────────────────────────

class TestPEIntegrity:
    def test_valid_pe(self):
        pe = _build_minimal_pe()
        result = check_file_integrity(bytes(pe), "pe")
        assert result["status"] == "healthy"
        assert result["detected_format"] == "pe"
        assert result["format_label"] == "PE"
        assert "pe_type" in result["format_details"]

    def test_missing_dos_magic(self):
        data = b"\x00\x00" + b"\x00" * 200
        issues, flags, details = _check_pe_integrity(data)
        assert _has_code(issues, "PE_DOS_MAGIC_MISSING")
        assert flags["header_corrupt"]

    def test_truncated_before_pe_sig(self):
        pe = _build_minimal_pe()
        # Truncate to just past DOS header but before PE sig area
        truncated = bytes(pe[:0x40])
        issues, flags, details = _check_pe_integrity(truncated)
        # Should detect e_lfanew OOB or truncation
        assert flags.get("header_corrupt") or flags.get("truncated") or _has_code(issues, "PE_LFANEW_OOB")

    def test_lfanew_oob(self):
        pe = _build_minimal_pe()
        # Set e_lfanew to point way past end of file
        struct.pack_into("<I", pe, 0x3C, 0xFFFFFF)
        issues, flags, details = _check_pe_integrity(bytes(pe))
        assert _has_code(issues, "PE_LFANEW_OOB")
        assert flags["header_corrupt"]

    def test_bad_pe_signature(self):
        pe = _build_minimal_pe()
        e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
        pe[e_lfanew:e_lfanew + 4] = b"XX\x00\x00"
        issues, flags, details = _check_pe_integrity(bytes(pe))
        assert _has_code(issues, "PE_SIGNATURE_CORRUPT")
        assert flags["header_corrupt"]

    def test_section_oob(self):
        pe = _build_minimal_pe()
        # Find section table and set raw pointer + size to exceed file
        e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
        coff = e_lfanew + 4
        opt_size = struct.unpack_from("<H", pe, coff + 16)[0]
        sec_off = coff + 20 + opt_size
        # Set SizeOfRawData to huge value, PointerToRawData to near end
        struct.pack_into("<II", pe, sec_off + 16, 0xFFFF, len(pe) - 10)
        issues, flags, details = _check_pe_integrity(bytes(pe))
        assert _has_code(issues, "PE_SECTION_OOB")
        assert flags["sections_oob"]

    def test_too_many_sections(self):
        pe = _build_minimal_pe()
        e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
        coff = e_lfanew + 4
        # Set num_sections to 200
        struct.pack_into("<H", pe, coff + 2, 200)
        issues, flags, details = _check_pe_integrity(bytes(pe))
        assert _has_code(issues, "PE_TOO_MANY_SECTIONS")

    def test_format_details_populated(self):
        pe = _build_minimal_pe()
        issues, flags, details = _check_pe_integrity(bytes(pe))
        assert "pe_type" in details
        assert "num_sections" in details
        assert "machine" in details

    def test_pe32plus(self):
        pe = _build_minimal_pe(pe_magic=0x20B)
        issues, flags, details = _check_pe_integrity(bytes(pe))
        assert details.get("pe_type") == "PE32+"

    def test_zero_entry_point(self):
        pe = _build_minimal_pe(entry_point=0)
        issues, flags, details = _check_pe_integrity(bytes(pe))
        assert _has_code(issues, "PE_ENTRY_POINT_ZERO")


# ── TestELFIntegrity ──────────────────────────────────────────────────────

class TestELFIntegrity:
    def test_valid_elf(self):
        elf = _build_minimal_elf()
        result = check_file_integrity(bytes(elf), "elf")
        assert result["status"] == "healthy"
        assert result["format_label"] == "ELF"
        assert "elf_class" in result["format_details"]

    def test_invalid_ei_class(self):
        elf = _build_minimal_elf()
        elf[4] = 0  # invalid class
        issues, flags, details = _check_elf_integrity(bytes(elf))
        assert _has_code(issues, "ELF_CLASS_INVALID")
        assert flags["header_corrupt"]

    def test_invalid_ei_data(self):
        elf = _build_minimal_elf()
        elf[5] = 0  # invalid endianness
        issues, flags, details = _check_elf_integrity(bytes(elf))
        assert _has_code(issues, "ELF_DATA_INVALID")
        assert flags["header_corrupt"]

    def test_section_headers_oob(self):
        elf = _build_minimal_elf(e_shoff=200, e_shnum=100)
        issues, flags, details = _check_elf_integrity(bytes(elf))
        assert _has_code(issues, "ELF_SHDR_OOB")
        assert flags["sections_oob"]

    def test_program_headers_oob(self):
        elf = _build_minimal_elf(e_phoff=200, e_phnum=100)
        issues, flags, details = _check_elf_integrity(bytes(elf))
        assert _has_code(issues, "ELF_PHDR_OOB")
        assert flags["sections_oob"]

    def test_elf32(self):
        elf = _build_minimal_elf(bits=32)
        result = check_file_integrity(bytes(elf), "elf")
        assert result["format_details"]["elf_class"] == "ELF32"

    def test_big_endian(self):
        elf = _build_minimal_elf(endian="big")
        result = check_file_integrity(bytes(elf), "elf")
        assert result["format_details"]["endianness"] == "big"


# ── TestMachoIntegrity ────────────────────────────────────────────────────

class TestMachoIntegrity:
    def test_valid_macho(self):
        macho = _build_minimal_macho_64()
        result = check_file_integrity(bytes(macho), "macho")
        # ncmds=0 gives a low-severity issue, so status is still healthy
        assert result["status"] == "healthy"
        assert result["format_label"] == "Mach-O"

    def test_cmds_oob(self):
        # Build a header claiming large sizeofcmds, then truncate
        macho = _build_minimal_macho_64(ncmds=5, sizeofcmds=16)
        # Overwrite sizeofcmds to exceed actual buffer
        struct.pack_into("<I", macho, 20, 0xFFFF)
        result = check_file_integrity(bytes(macho), "macho")
        assert any(i["code"] == "MACHO_CMDS_OOB" for i in result["issues"])

    def test_cmdsize_zero(self):
        # Build a macho with 1 load command that has cmdsize=0
        hdr_size = 32
        buf = bytearray(hdr_size + 16)
        struct.pack_into("<I", buf, 0, 0xFEEDFACF)  # magic
        struct.pack_into("<II", buf, 4, 0x01000007, 3)  # cputype, cpusubtype
        struct.pack_into("<I", buf, 12, 2)  # filetype
        struct.pack_into("<I", buf, 16, 1)  # ncmds
        struct.pack_into("<I", buf, 20, 8)  # sizeofcmds
        # Load command with cmdsize=0
        struct.pack_into("<II", buf, hdr_size, 1, 0)  # cmd=1, cmdsize=0
        result = check_file_integrity(bytes(buf), "macho")
        assert any(i["code"] == "MACHO_CMDSIZE_ZERO" for i in result["issues"])

    def test_unknown_filetype(self):
        macho = _build_minimal_macho_64(filetype=99)
        result = check_file_integrity(bytes(macho), "macho")
        assert any(i["code"] == "MACHO_UNKNOWN_FILETYPE" for i in result["issues"])


# ── TestClassifyStatus ────────────────────────────────────────────────────

class TestClassifyStatus:
    def test_no_issues(self):
        status, conf = _classify_status([], _empty_flags())
        assert status == "healthy"
        assert conf == "high"

    def test_critical_issue(self):
        issues = [_issue("critical", "TEST", "test")]
        status, conf = _classify_status(issues, _empty_flags())
        assert status == "corrupt"

    def test_high_issue(self):
        issues = [_issue("high", "TEST", "test")]
        status, conf = _classify_status(issues, _empty_flags())
        assert status == "partial"

    def test_medium_issue(self):
        issues = [_issue("medium", "TEST", "test")]
        status, conf = _classify_status(issues, _empty_flags())
        assert status == "suspicious"

    def test_info_only(self):
        issues = [_issue("info", "TEST", "test")]
        status, conf = _classify_status(issues, _empty_flags())
        assert status == "healthy"

    def test_mixed_severities(self):
        issues = [
            _issue("info", "A", "a"),
            _issue("high", "B", "b"),
            _issue("low", "C", "c"),
        ]
        status, conf = _classify_status(issues, _empty_flags())
        assert status == "partial"  # worst is high


# ── TestCheckFileIntegrity (top-level) ────────────────────────────────────

class TestCheckFileIntegrity:
    def test_return_schema(self):
        result = check_file_integrity(b"\x00" * 100, "unknown")
        required_keys = {
            "status", "confidence", "file_size", "detected_format",
            "format_label", "entropy", "null_ratio", "issues",
            "flags", "format_details", "recommendation",
        }
        assert required_keys <= set(result.keys())
        assert isinstance(result["issues"], list)
        assert isinstance(result["flags"], dict)
        assert isinstance(result["format_details"], dict)
        assert isinstance(result["entropy"], float)
        assert isinstance(result["null_ratio"], float)

    def test_unknown_format(self):
        result = check_file_integrity(b"hello world" * 100, "unknown")
        assert result["format_label"] == "Unknown"
        assert result["format_details"] == {}

    def test_shellcode_mode(self):
        result = check_file_integrity(b"\xcc" * 200, "shellcode")
        assert result["format_label"] == "Shellcode/Raw"

    def test_issues_capped(self):
        # Large data that would generate many issues is handled
        result = check_file_integrity(b"\x00" * 100, "pe")
        assert len(result["issues"]) <= INTEGRITY_MAX_ISSUES

    def test_healthy_pe_recommendation(self):
        pe = _build_minimal_pe()
        result = check_file_integrity(bytes(pe), "pe")
        assert "healthy" in result["recommendation"].lower() or "proceed" in result["recommendation"].lower()

    def test_corrupt_pe_recommendation(self):
        result = check_file_integrity(b"\x00" * 100, "pe")
        assert result["status"] in ("corrupt", "partial", "suspicious")
        assert len(result["recommendation"]) > 0
