"""Pure-Python gopclntab parser for Go binaries.

Parses the .gopclntab (Program Counter Line Table) region embedded in Go
binaries to recover function names, addresses, source file paths, and line
numbers.  Works on stripped binaries — gopclntab survives ``-ldflags="-s -w"``.

Supports Go 1.2–1.26+ across four format versions identified by magic bytes.
Handles ELF (.gopclntab section), Mach-O (__gopclntab section), and PE
(magic-byte scan).

Based on r2gopclntabParser by Asher Davila (MIT License).
Adapted for Arkana: r2pipe dependency removed, pure-struct parsing,
comprehensive error handling matching Arkana's defensive coding standards.

Original source: https://github.com/AsherDLL/r2gopclntabParser
"""

import logging
import struct
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Magic bytes (little-endian uint32) → version label
_GOPCLNTAB_MAGICS: Dict[int, str] = {
    0xFFFFFFF1: "1.20+",
    0xFFFFFFF0: "1.18",
    0xFFFFFFFA: "1.16",
    0xFFFFFFFB: "1.2",
}

# LE byte patterns for magic scan
_MAGIC_PATTERNS_LE: List[bytes] = [
    b"\xf1\xff\xff\xff",  # Go 1.20+
    b"\xf0\xff\xff\xff",  # Go 1.18
    b"\xfa\xff\xff\xff",  # Go 1.16
    b"\xfb\xff\xff\xff",  # Go 1.2
]

# BE byte patterns for magic scan
_MAGIC_PATTERNS_BE: List[bytes] = [
    b"\xff\xff\xff\xf1",
    b"\xff\xff\xff\xf0",
    b"\xff\xff\xff\xfa",
    b"\xff\xff\xff\xfb",
]

# Section names that contain gopclntab data
_GOPCLNTAB_SECTION_NAMES = frozenset({
    ".gopclntab",
    ".data.rel.ro.gopclntab",
    "__gopclntab",
})

# Safety caps
_MAX_FUNCTIONS = 500_000
_MAX_SOURCE_FILES = 50_000
_MAX_NAME_LEN = 512
_MAX_SCAN_SIZE = 64 * 1024 * 1024  # 64 MB
_MAX_LINE_INFO = 5_000  # per function
_MIN_SECTION_SIZE = 16  # minimum viable gopclntab region


# ---------------------------------------------------------------------------
# Low-level struct helpers (bounds-checked)
# ---------------------------------------------------------------------------

def _read_u8(data: bytes, off: int) -> Optional[int]:
    if off < 0 or off >= len(data):
        return None
    return data[off]


def _read_u32(data: bytes, off: int, big_endian: bool = False) -> Optional[int]:
    if off < 0 or off + 4 > len(data):
        return None
    fmt = ">I" if big_endian else "<I"
    return struct.unpack_from(fmt, data, off)[0]


def _read_i32(data: bytes, off: int, big_endian: bool = False) -> Optional[int]:
    if off < 0 or off + 4 > len(data):
        return None
    fmt = ">i" if big_endian else "<i"
    return struct.unpack_from(fmt, data, off)[0]


def _read_u64(data: bytes, off: int, big_endian: bool = False) -> Optional[int]:
    if off < 0 or off + 8 > len(data):
        return None
    fmt = ">Q" if big_endian else "<Q"
    return struct.unpack_from(fmt, data, off)[0]


def _read_ptr(data: bytes, off: int, ptr_size: int, big_endian: bool = False) -> Optional[int]:
    """Read a pointer-sized value (4 or 8 bytes)."""
    if ptr_size == 8:
        return _read_u64(data, off, big_endian)
    return _read_u32(data, off, big_endian)


def _read_u16(data: bytes, off: int, big_endian: bool = False) -> Optional[int]:
    if off < 0 or off + 2 > len(data):
        return None
    fmt = ">H" if big_endian else "<H"
    return struct.unpack_from(fmt, data, off)[0]


def _read_cstring(data: bytes, off: int, max_len: int = _MAX_NAME_LEN) -> str:
    """Read a null-terminated string with bounds and length cap."""
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, off + max_len)
    if end == -1:
        end = min(off + max_len, len(data))
    return data[off:end].decode("utf-8", errors="replace")


def _decode_varint(data: bytes, off: int) -> Tuple[int, int]:
    """Decode an unsigned variable-length integer.

    Returns (value, bytes_consumed).  Returns (0, 0) on truncated input.
    """
    result = 0
    shift = 0
    consumed = 0
    while off + consumed < len(data):
        b = data[off + consumed]
        result |= (b & 0x7F) << shift
        consumed += 1
        if (b & 0x80) == 0:
            break
        shift += 7
        if shift > 63:
            break  # prevent infinite loop on corrupt data
    return result, consumed


def _decode_pcdata(data: bytes, off: int, quantum: int,
                   max_entries: int = _MAX_LINE_INFO):
    """Decode a PC data sequence from pctab.

    Yields (pc_offset, value) tuples.  pc_offset is cumulative from the
    function's entry.
    """
    pos = off
    pc = 0
    val = -1
    count = 0

    while pos < len(data) and count < max_entries:
        # Value delta (zig-zag encoded)
        uvdelta, n = _decode_varint(data, pos)
        if n == 0:
            break
        if uvdelta == 0 and pc != 0:
            break  # end of sequence
        pos += n

        # Zig-zag decode
        if uvdelta & 1:
            sdelta = -((uvdelta + 1) >> 1)
        else:
            sdelta = uvdelta >> 1

        val += sdelta

        # PC delta (unsigned)
        if pos >= len(data):
            break
        pcdelta, n = _decode_varint(data, pos)
        if n == 0:
            break
        pos += n

        pc += pcdelta * quantum
        count += 1
        yield (pc, val)


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------

class _PcHeader:
    """Parsed gopclntab header."""

    __slots__ = (
        "magic", "version", "ptr_size", "quantum", "nfunc", "nfiles",
        "text_start", "funcname_off", "cu_off", "filetab_off",
        "pctab_off", "pclntab_off", "functab_off_in_section",
        "big_endian",
    )

    def __init__(self):
        self.magic: int = 0
        self.version: str = "unknown"
        self.ptr_size: int = 0
        self.quantum: int = 0
        self.nfunc: int = 0
        self.nfiles: int = 0
        self.text_start: int = 0
        self.funcname_off: int = 0
        self.cu_off: int = 0
        self.filetab_off: int = 0
        self.pctab_off: int = 0
        self.pclntab_off: int = 0
        self.functab_off_in_section: int = 0
        self.big_endian: bool = False

    @property
    def is_12(self) -> bool:
        return self.magic == 0xFFFFFFFB

    @property
    def is_116(self) -> bool:
        return self.magic == 0xFFFFFFFA

    @property
    def is_118(self) -> bool:
        return self.magic == 0xFFFFFFF0

    @property
    def is_120(self) -> bool:
        return self.magic == 0xFFFFFFF1


def _parse_header(data: bytes, base: int, errors: List[str]) -> Optional[_PcHeader]:
    """Parse a gopclntab header at *base* in *data*.

    Returns ``None`` on invalid/truncated data.
    """
    if base + 8 > len(data):
        errors.append(f"Header truncated at offset 0x{base:x}")
        return None

    h = _PcHeader()

    # First 8 bytes are architecture-independent
    magic_le = _read_u32(data, base, big_endian=False)
    if magic_le in _GOPCLNTAB_MAGICS:
        h.big_endian = False
        h.magic = magic_le
    else:
        magic_be = _read_u32(data, base, big_endian=True)
        if magic_be in _GOPCLNTAB_MAGICS:
            h.big_endian = True
            h.magic = magic_be
        else:
            errors.append(f"Unknown gopclntab magic at 0x{base:x}: "
                          f"0x{magic_le:08X} (LE) / 0x{(magic_be or 0):08X} (BE)")
            return None

    h.version = _GOPCLNTAB_MAGICS[h.magic]
    be = h.big_endian

    pad1 = _read_u8(data, base + 4)
    pad2 = _read_u8(data, base + 5)
    if pad1 is None or pad2 is None or pad1 != 0 or pad2 != 0:
        errors.append(f"Invalid padding bytes at 0x{base:x}: pad1={pad1}, pad2={pad2}")
        return None

    quantum = _read_u8(data, base + 6)
    ptr_size = _read_u8(data, base + 7)
    if quantum is None or quantum not in (1, 2, 4):
        errors.append(f"Invalid quantum {quantum} at 0x{base:x}")
        return None
    if ptr_size is None or ptr_size not in (4, 8):
        errors.append(f"Invalid pointer size {ptr_size} at 0x{base:x}")
        return None

    h.quantum = quantum
    h.ptr_size = ptr_size
    ps = ptr_size

    off = base + 8

    if h.is_12:
        # Go 1.2: magic(4) + pad(2) + quantum(1) + ptrsize(1) + nfunc(ps)
        nfunc = _read_ptr(data, off, ps, be)
        if nfunc is None:
            errors.append("Truncated Go 1.2 header (nfunc)")
            return None
        h.nfunc = nfunc
        h.functab_off_in_section = off + ps - base

    elif h.is_116:
        # Go 1.16: + nfunc(ps) + nfiles(ps) + funcnameOff(ps) + cuOff(ps)
        #          + filetabOff(ps) + pctabOff(ps) + pclnOff(ps)
        needed = ps * 7
        if off + needed > len(data):
            errors.append("Truncated Go 1.16 header")
            return None
        h.nfunc = _read_ptr(data, off, ps, be) or 0; off += ps
        h.nfiles = _read_ptr(data, off, ps, be) or 0; off += ps
        h.funcname_off = _read_ptr(data, off, ps, be) or 0; off += ps
        h.cu_off = _read_ptr(data, off, ps, be) or 0; off += ps
        h.filetab_off = _read_ptr(data, off, ps, be) or 0; off += ps
        h.pctab_off = _read_ptr(data, off, ps, be) or 0; off += ps
        h.pclntab_off = _read_ptr(data, off, ps, be) or 0

    else:
        # Go 1.18+: + nfunc(ps) + nfiles(ps) + textStart(ps) + funcnameOff(ps)
        #           + cuOff(ps) + filetabOff(ps) + pctabOff(ps) + pclnOff(ps)
        needed = ps * 8
        if off + needed > len(data):
            errors.append(f"Truncated Go {h.version} header")
            return None
        h.nfunc = _read_ptr(data, off, ps, be) or 0; off += ps
        h.nfiles = _read_ptr(data, off, ps, be) or 0; off += ps
        h.text_start = _read_ptr(data, off, ps, be) or 0; off += ps
        h.funcname_off = _read_ptr(data, off, ps, be) or 0; off += ps
        h.cu_off = _read_ptr(data, off, ps, be) or 0; off += ps
        h.filetab_off = _read_ptr(data, off, ps, be) or 0; off += ps
        h.pctab_off = _read_ptr(data, off, ps, be) or 0; off += ps
        h.pclntab_off = _read_ptr(data, off, ps, be) or 0

    return h


# ---------------------------------------------------------------------------
# Section / magic scan
# ---------------------------------------------------------------------------

def _find_by_section_name(
    file_data: bytes,
    sections: List[Dict[str, Any]],
) -> Optional[Tuple[int, int]]:
    """Find gopclntab via section name.  Returns (file_offset, size) or None."""
    for sec in sections:
        name = sec.get("name", "")
        if name in _GOPCLNTAB_SECTION_NAMES:
            offset = sec.get("offset", 0)
            size = sec.get("size", 0)
            if size < _MIN_SECTION_SIZE:
                continue
            if offset < 0 or offset + size > len(file_data):
                continue
            return (offset, size)
    return None


def _find_by_magic_scan(
    file_data: bytes,
    max_scan: int = _MAX_SCAN_SIZE,
) -> Optional[int]:
    """Scan raw bytes for gopclntab magic with header validation.

    Returns the file offset of the valid header, or None.
    """
    scan_end = min(len(file_data), max_scan)
    patterns = _MAGIC_PATTERNS_LE + _MAGIC_PATTERNS_BE

    for pat in patterns:
        idx = 0
        while idx < scan_end:
            pos = file_data.find(pat, idx, scan_end)
            if pos == -1:
                break
            # Validate header fields after magic
            if pos + 8 <= len(file_data):
                pad1 = file_data[pos + 4]
                pad2 = file_data[pos + 5]
                quantum = file_data[pos + 6]
                ptr_size = file_data[pos + 7]
                if (pad1 == 0 and pad2 == 0
                        and ptr_size in (4, 8)
                        and quantum in (1, 2, 4)):
                    logger.debug("gopclntab magic found at file offset 0x%x", pos)
                    return pos
            idx = pos + 1

    return None


# ---------------------------------------------------------------------------
# Minimal ELF section header parser
# ---------------------------------------------------------------------------

def _parse_elf_section_headers(data: bytes) -> List[Dict[str, Any]]:
    """Extract section headers from an ELF binary using only struct.

    Returns list of dicts with keys: name, offset, size, vaddr.
    Returns empty list on any parse error.
    """
    try:
        if len(data) < 64 or data[:4] != b"\x7fELF":
            return []

        ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = data[5]   # 1 = LE, 2 = BE
        be = ei_data == 2

        if ei_class == 2:
            # ELF64
            if len(data) < 64:
                return []
            e_shoff = _read_u64(data, 40, be) or 0
            e_shentsize = _read_u16(data, 58, be)
            e_shnum = _read_u16(data, 60, be)
            e_shstrndx = _read_u16(data, 62, be)
        elif ei_class == 1:
            # ELF32
            if len(data) < 52:
                return []
            e_shoff = _read_u32(data, 32, be) or 0
            e_shentsize = _read_u16(data, 46, be)
            e_shnum = _read_u16(data, 48, be)
            e_shstrndx = _read_u16(data, 50, be)
        else:
            return []

        if e_shoff == 0 or e_shnum == 0 or e_shentsize == 0:
            return []
        if e_shoff + e_shnum * e_shentsize > len(data):
            return []

        # Read string table section header to get section names
        strtab_off_in_file = 0
        if e_shstrndx < e_shnum:
            str_sh_off = e_shoff + e_shstrndx * e_shentsize
            if ei_class == 2:
                strtab_off_in_file = _read_u64(data, str_sh_off + 24, be) or 0
            else:
                strtab_off_in_file = _read_u32(data, str_sh_off + 16, be) or 0

        sections = []
        for i in range(e_shnum):
            sh_off = e_shoff + i * e_shentsize
            if sh_off + e_shentsize > len(data):
                break

            sh_name_idx = _read_u32(data, sh_off, be) or 0

            if ei_class == 2:
                sh_addr = _read_u64(data, sh_off + 16, be) or 0
                sh_offset = _read_u64(data, sh_off + 24, be) or 0
                sh_size = _read_u64(data, sh_off + 32, be) or 0
            else:
                sh_addr = _read_u32(data, sh_off + 12, be) or 0
                sh_offset = _read_u32(data, sh_off + 16, be) or 0
                sh_size = _read_u32(data, sh_off + 20, be) or 0

            # Resolve name from string table
            name = ""
            if strtab_off_in_file and sh_name_idx:
                name = _read_cstring(data, strtab_off_in_file + sh_name_idx, 64)

            sections.append({
                "name": name,
                "offset": sh_offset,
                "size": sh_size,
                "vaddr": sh_addr,
            })

        return sections
    except Exception as e:
        logger.debug("ELF section header parse failed: %s", e)
        return []


# ---------------------------------------------------------------------------
# Minimal Mach-O section header parser
# ---------------------------------------------------------------------------

def _parse_macho_section_headers(data: bytes) -> List[Dict[str, Any]]:
    """Extract section headers from a Mach-O binary using only struct.

    Returns list of dicts with keys: name, offset, size, vaddr.
    Returns empty list on any parse error.
    """
    try:
        if len(data) < 28:
            return []

        magic = struct.unpack_from("<I", data, 0)[0]
        if magic == 0xFEEDFACE:
            is_64 = False
            be = False
        elif magic == 0xFEEDFACF:
            is_64 = True
            be = False
        elif magic == 0xCEFAEDFE:
            is_64 = False
            be = True
        elif magic == 0xCFFAEDFE:
            is_64 = True
            be = True
        else:
            return []

        header_size = 32 if is_64 else 28
        if len(data) < header_size:
            return []

        ncmds = _read_u32(data, 16, be) or 0
        if ncmds > 10000:
            return []

        off = header_size
        sections = []

        for _ in range(ncmds):
            if off + 8 > len(data):
                break
            cmd = _read_u32(data, off, be) or 0
            cmdsize = _read_u32(data, off + 4, be) or 0
            if cmdsize < 8:
                break

            # LC_SEGMENT (1) or LC_SEGMENT_64 (0x19)
            if cmd in (1, 0x19):
                if cmd == 0x19:
                    nsects = _read_u32(data, off + 64, be) or 0
                    sec_off = off + 72
                    sec_size = 80
                else:
                    nsects = _read_u32(data, off + 48, be) or 0
                    sec_off = off + 56
                    sec_size = 68

                for j in range(min(nsects, 1000)):
                    s_off = sec_off + j * sec_size
                    if s_off + sec_size > len(data):
                        break

                    # Section name is first 16 bytes (null-padded)
                    sec_name = data[s_off:s_off + 16].split(b"\x00", 1)[0]
                    sec_name_str = sec_name.decode("utf-8", errors="replace")

                    if cmd == 0x19:
                        s_addr = _read_u64(data, s_off + 32, be) or 0
                        s_size = _read_u64(data, s_off + 40, be) or 0
                        s_foff = _read_u32(data, s_off + 48, be) or 0
                    else:
                        s_addr = _read_u32(data, s_off + 32, be) or 0
                        s_size = _read_u32(data, s_off + 36, be) or 0
                        s_foff = _read_u32(data, s_off + 40, be) or 0

                    sections.append({
                        "name": sec_name_str,
                        "offset": s_foff,
                        "size": s_size,
                        "vaddr": s_addr,
                    })

            off += cmdsize

        return sections
    except Exception as e:
        logger.debug("Mach-O section header parse failed: %s", e)
        return []


# ---------------------------------------------------------------------------
# Function table walkers
# ---------------------------------------------------------------------------

def _parse_functions_v12(
    data: bytes, header: _PcHeader, base: int, errors: List[str],
) -> List[Dict[str, Any]]:
    """Parse function table for Go 1.2–1.15."""
    functions = []
    be = header.big_endian
    ps = header.ptr_size
    nfunc = min(header.nfunc, _MAX_FUNCTIONS)
    if header.nfunc > _MAX_FUNCTIONS:
        errors.append(f"Function count {header.nfunc} capped to {_MAX_FUNCTIONS}")

    tab_start = base + header.functab_off_in_section
    entry_size = ps * 2

    for i in range(nfunc):
        try:
            off = tab_start + i * entry_size
            if off + entry_size > len(data):
                errors.append(f"Function table truncated at entry {i}/{nfunc}")
                break

            entry_addr = _read_ptr(data, off, ps, be)
            func_off = _read_ptr(data, off + ps, ps, be)
            if entry_addr is None or func_off is None:
                continue

            func_data_off = base + func_off
            if func_data_off + ps + 4 > len(data):
                continue

            name_off = _read_i32(data, func_data_off + ps, be)
            if name_off is None:
                continue

            name = ""
            if 0 <= name_off < len(data) - base:
                name = _read_cstring(data, base + name_off)

            functions.append({
                "name": name,
                "address": entry_addr,
            })
        except (struct.error, IndexError, ValueError) as e:
            errors.append(f"Function {i}: {type(e).__name__}: {str(e)[:200]}")
            continue

    return functions


def _parse_functions_v116(
    data: bytes, header: _PcHeader, base: int, errors: List[str],
) -> List[Dict[str, Any]]:
    """Parse function table for Go 1.16–1.17."""
    functions = []
    be = header.big_endian
    ps = header.ptr_size
    nfunc = min(header.nfunc, _MAX_FUNCTIONS)
    if header.nfunc > _MAX_FUNCTIONS:
        errors.append(f"Function count {header.nfunc} capped to {_MAX_FUNCTIONS}")

    pclntab_off = base + header.pclntab_off
    funcname_off = base + header.funcname_off
    entry_size = ps * 2

    for i in range(nfunc):
        try:
            off = pclntab_off + i * entry_size
            if off + entry_size > len(data):
                errors.append(f"Function table truncated at entry {i}/{nfunc}")
                break

            entry_addr = _read_ptr(data, off, ps, be)
            func_off_val = _read_ptr(data, off + ps, ps, be)
            if entry_addr is None or func_off_val is None:
                continue

            func_data_off = pclntab_off + func_off_val
            if func_data_off + ps + 8 > len(data):
                continue

            name_off = _read_i32(data, func_data_off + ps, be)
            if name_off is None:
                continue

            name = ""
            abs_name = funcname_off + name_off
            if 0 <= abs_name < len(data):
                name = _read_cstring(data, abs_name)

            functions.append({
                "name": name,
                "address": entry_addr,
            })
        except (struct.error, IndexError, ValueError) as e:
            errors.append(f"Function {i}: {type(e).__name__}: {str(e)[:200]}")
            continue

    return functions


def _parse_functions_v118_plus(
    data: bytes, header: _PcHeader, base: int,
    text_base: int, errors: List[str],
) -> List[Dict[str, Any]]:
    """Parse function table for Go 1.18+ (including 1.20+)."""
    functions = []
    be = header.big_endian
    nfunc = min(header.nfunc, _MAX_FUNCTIONS)
    if header.nfunc > _MAX_FUNCTIONS:
        errors.append(f"Function count {header.nfunc} capped to {_MAX_FUNCTIONS}")

    pclntab_off = base + header.pclntab_off
    funcname_off = base + header.funcname_off
    pctab_off = base + header.pctab_off
    cu_off = base + header.cu_off
    filetab_off = base + header.filetab_off
    entry_size = 8  # two uint32 fields for Go 1.18+

    for i in range(nfunc):
        try:
            off = pclntab_off + i * entry_size
            if off + entry_size > len(data):
                errors.append(f"Function table truncated at entry {i}/{nfunc}")
                break

            entry_off_val = _read_u32(data, off, be)
            func_off_val = _read_u32(data, off + 4, be)
            if entry_off_val is None or func_off_val is None:
                continue

            func_data_off = pclntab_off + func_off_val

            # _func struct: entryOff(4) + nameOff(4) + args(4) + deferreturn(4)
            # + pcsp(4) + pcfile(4) + pcln(4) + npcdata(4) + cuOffset(4)
            # Go 1.20+ adds startLine(4) before funcID
            min_func_size = 44 if header.is_120 else 40
            if func_data_off + min_func_size > len(data):
                continue

            f_nameoff = _read_i32(data, func_data_off + 4, be)
            f_pcfile = _read_u32(data, func_data_off + 20, be)
            f_cuoffset = _read_u32(data, func_data_off + 32, be)

            start_line = 0
            if header.is_120:
                start_line = _read_i32(data, func_data_off + 36, be) or 0

            # Resolve name
            name = ""
            if f_nameoff is not None:
                abs_name = funcname_off + f_nameoff
                if 0 <= abs_name < len(data):
                    name = _read_cstring(data, abs_name)

            abs_addr = text_base + entry_off_val

            # Resolve source file (first pcfile entry)
            source_file = ""
            if (f_pcfile is not None and f_pcfile != 0
                    and pctab_off + f_pcfile < len(data)
                    and f_cuoffset is not None):
                try:
                    for (_pc, fileidx) in _decode_pcdata(
                            data, pctab_off + f_pcfile, header.quantum, max_entries=1):
                        cu_idx = f_cuoffset + fileidx
                        cu_table_off = cu_off + cu_idx * 4
                        if 0 <= cu_table_off < len(data) - 4:
                            file_off = _read_u32(data, cu_table_off, be)
                            if (file_off is not None
                                    and file_off != 0xFFFFFFFF
                                    and filetab_off + file_off < len(data)):
                                source_file = _read_cstring(data, filetab_off + file_off)
                        break
                except Exception:
                    pass  # Source file resolution is best-effort

            func_entry: Dict[str, Any] = {
                "name": name,
                "address": abs_addr,
            }
            if source_file:
                func_entry["source_file"] = source_file
            if start_line:
                func_entry["start_line"] = start_line

            functions.append(func_entry)
        except (struct.error, IndexError, ValueError) as e:
            errors.append(f"Function {i}: {type(e).__name__}: {str(e)[:200]}")
            continue

    return functions


# ---------------------------------------------------------------------------
# Source file extraction
# ---------------------------------------------------------------------------

def _parse_source_files(
    data: bytes, header: _PcHeader, base: int, errors: List[str],
) -> List[str]:
    """Extract source file paths from filetab (Go 1.16+)."""
    if header.is_12:
        return []

    filetab_off = base + header.filetab_off
    if filetab_off == 0 or filetab_off >= len(data):
        return []

    files: List[str] = []
    seen: set = set()
    pos = filetab_off
    limit = min(len(data), filetab_off + 0x1000000)  # 16 MB scan cap
    max_files = min(header.nfiles, _MAX_SOURCE_FILES) if header.nfiles > 0 else _MAX_SOURCE_FILES

    while pos < limit and len(files) < max_files:
        s = _read_cstring(data, pos, max_len=1024)
        if not s:
            pos += 1
            continue
        if s not in seen:
            files.append(s)
            seen.add(s)
        pos += len(s.encode("utf-8", errors="replace")) + 1

    return files


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_gopclntab(
    file_data: bytes,
    sections: Optional[List[Dict[str, Any]]] = None,
    text_vaddr: int = 0,
) -> Optional[Dict[str, Any]]:
    """Parse gopclntab from raw binary data.

    Args:
        file_data: Raw binary file contents.
        sections: Optional list of section dicts with keys:
            ``name``, ``offset``, ``size``, ``vaddr``.
            Used for section-name-based lookup.  If None or empty,
            falls back to magic-byte scan.
        text_vaddr: Virtual address of .text section.  Used for Go 1.18+
            when the header's ``textStart`` is 0 (PIE binaries).

    Returns:
        ``None`` if no gopclntab found (not a Go binary).
        Otherwise a dict with:
            ``go_version_hint``, ``pointer_size``, ``quantum``,
            ``functions``, ``source_files``, ``function_count``,
            ``source_file_count``, ``parse_errors``.
    """
    errors: List[str] = []

    if len(file_data) < _MIN_SECTION_SIZE:
        return None

    # --- Locate gopclntab region ---
    pclntab_offset = None
    pclntab_size = None

    if sections:
        found = _find_by_section_name(file_data, sections)
        if found:
            pclntab_offset, pclntab_size = found
            logger.debug("gopclntab found via section name at offset 0x%x, size 0x%x",
                         pclntab_offset, pclntab_size)

    if pclntab_offset is None:
        pclntab_offset = _find_by_magic_scan(file_data)
        if pclntab_offset is not None:
            pclntab_size = len(file_data) - pclntab_offset
            logger.debug("gopclntab found via magic scan at offset 0x%x", pclntab_offset)

    if pclntab_offset is None:
        return None  # Not a Go binary — no gopclntab found

    # Work with the gopclntab region
    pclntab_data = file_data[pclntab_offset:pclntab_offset + pclntab_size]
    base = 0  # offsets within pclntab_data are relative to start

    # --- Parse header ---
    header = _parse_header(pclntab_data, base, errors)
    if header is None:
        logger.warning("gopclntab header parse failed: %s", errors)
        return None

    if header.nfunc <= 0:
        return {
            "go_version_hint": header.version,
            "pointer_size": header.ptr_size,
            "quantum": header.quantum,
            "functions": [],
            "source_files": [],
            "function_count": 0,
            "source_file_count": 0,
            "parse_errors": errors,
        }

    # --- Resolve textStart ---
    text_base = 0
    if header.is_118 or header.is_120:
        if header.text_start != 0:
            text_base = header.text_start
        elif text_vaddr != 0:
            text_base = text_vaddr
    elif header.is_116:
        text_base = text_vaddr
    # Go 1.2: text_base stays 0 (absolute addresses)

    # --- Parse functions ---
    if header.is_12:
        functions = _parse_functions_v12(pclntab_data, header, base, errors)
    elif header.is_116:
        functions = _parse_functions_v116(pclntab_data, header, base, errors)
    else:
        functions = _parse_functions_v118_plus(
            pclntab_data, header, base, text_base, errors)

    # --- Parse source files ---
    source_files = _parse_source_files(pclntab_data, header, base, errors)

    return {
        "go_version_hint": header.version,
        "pointer_size": header.ptr_size,
        "quantum": header.quantum,
        "functions": functions,
        "source_files": source_files,
        "function_count": len(functions),
        "source_file_count": len(source_files),
        "parse_errors": errors,
    }
