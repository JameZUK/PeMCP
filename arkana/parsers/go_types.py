"""Pure-Python parser for Go runtime type descriptors.

Parses Go's embedded type metadata from compiled binaries to extract struct
field layouts, interface method sets, and interface-to-concrete dispatch tables
(itabs).  Works alongside ``go_pclntab.py`` to provide deeper type information
for Go binary reverse engineering.

Supports Go 1.7–1.26+ across ELF, Mach-O, and PE formats.

Go type metadata layout (from reflect/type.go and internal/abi/type.go):
    - ``runtime._type`` — base type descriptor (size, kind, name, etc.)
    - ``runtime.structtype`` — extends _type with field list
    - ``runtime.interfacetype`` — extends _type with method set
    - ``runtime.itab`` — interface→concrete dispatch tables

This parser works with typelink and itab sections, which are separate from
gopclntab and contain the type system metadata.

References:
    - https://go.dev/src/internal/abi/type.go
    - https://go.dev/src/reflect/type.go
"""

import logging
import re
import struct
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Go reflect.Kind values (stable since Go 1.0)
_GO_KINDS = {
    0: "invalid",
    1: "bool",
    2: "int",
    3: "int8",
    4: "int16",
    5: "int32",
    6: "int64",
    7: "uint",
    8: "uint8",
    9: "uint16",
    10: "uint32",
    11: "uint64",
    12: "uintptr",
    13: "float32",
    14: "float64",
    15: "complex64",
    16: "complex128",
    17: "array",
    18: "chan",
    19: "func",
    20: "interface",
    21: "map",
    22: "pointer",
    23: "slice",
    24: "string",
    25: "struct",
    26: "unsafepointer",
}

# tflag bit masks (Go 1.7+)
_TFLAG_UNCOMMON = 1 << 0
_TFLAG_EXTRA_STAR = 1 << 1
_TFLAG_NAMED = 1 << 2

# Section names for typelink and itab data
_TYPELINK_SECTION_NAMES = frozenset({
    ".typelink", ".data.rel.ro.typelink", "__typelink",
})
_ITAB_SECTION_NAMES = frozenset({
    ".itablink", ".go.itab", "__itablink",
    ".data.rel.ro.go.itab", ".data.rel.ro.itablink",
})
_RODATA_SECTION_NAMES = frozenset({
    ".rodata", ".data.rel.ro", "__rodata",
    ".rdata",  # PE
})

# Safety caps
_MAX_TYPES = 5_000
_MAX_FIELDS_PER_STRUCT = 200
_MAX_METHODS_PER_INTERFACE = 100
_MAX_ITABS = 10_000
_MAX_NAME_LEN = 512


# ---------------------------------------------------------------------------
# Low-level struct helpers (mirroring go_pclntab.py patterns)
# ---------------------------------------------------------------------------

def _read_u8(data: bytes, off: int) -> Optional[int]:
    if off < 0 or off >= len(data):
        return None
    return data[off]


def _read_u16(data: bytes, off: int, big_endian: bool = False) -> Optional[int]:
    if off < 0 or off + 2 > len(data):
        return None
    fmt = ">H" if big_endian else "<H"
    return struct.unpack_from(fmt, data, off)[0]


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


def _read_name(data: bytes, off: int, max_len: int = _MAX_NAME_LEN) -> Optional[str]:
    """Read a Go name from data at the given offset.

    Go names are encoded as: [flags_byte] [len_hi] [len_lo] [name_bytes...]
    The first byte contains flags (exported, etc.), bytes 1-2 are the length.
    """
    if off < 0 or off + 3 > len(data):
        return None
    name_len = (data[off + 1] << 8) | data[off + 2]
    if name_len <= 0 or name_len > max_len:
        return None
    end = off + 3 + name_len
    if end > len(data):
        return None
    try:
        return data[off + 3: end].decode("utf-8", errors="replace")
    except Exception:
        return None


def _read_name_v117(
    data: bytes, type_addr_off: int, name_off_rel: int,
    max_len: int = _MAX_NAME_LEN,
) -> Optional[str]:
    """Read a Go name using relative offset (Go 1.17+).

    In Go 1.17+, name offsets are relative to the type descriptor address,
    not absolute.
    """
    abs_off = type_addr_off + name_off_rel
    return _read_name(data, abs_off, max_len)


# ---------------------------------------------------------------------------
# Section location helpers
# ---------------------------------------------------------------------------

def _find_section(
    sections: List[Dict[str, Any]],
    target_names: frozenset,
) -> Optional[Dict[str, Any]]:
    """Find a section by name from a list of section dicts."""
    lower_names = {n.lower() for n in target_names}
    for sec in sections:
        name = sec.get("name", "")
        if isinstance(name, str) and name.lower() in lower_names:
            return sec
    return None


def _get_section_data(
    file_data: bytes,
    section: Dict[str, Any],
) -> Optional[bytes]:
    """Extract section data from the binary."""
    offset = section.get("offset", 0)
    size = section.get("size", 0)
    if offset < 0 or size <= 0 or offset + size > len(file_data):
        return None
    return file_data[offset: offset + size]


# ---------------------------------------------------------------------------
# Type descriptor parsing
# ---------------------------------------------------------------------------

class _TypeLayout:
    """Describes the binary layout of runtime._type for a Go version.

    Layout varies across Go versions:
        Go 1.7-1.16: size(ptr) + ptrdata(ptr) + hash(4) + tflag(1) + align(1)
                      + fieldAlign(1) + kind(1) + equal(ptr) + gcdata(ptr)
                      + str(i32) + ptrToThis(i32)
        Go 1.17+:     Same but str offset is relative to the type's address
        Go 1.18+:     Same as 1.17+ (generics add type params but base layout unchanged)
    """

    def __init__(self, ptr_size: int, relative_names: bool = False):
        self.ptr_size = ptr_size
        self.relative_names = relative_names  # Go 1.17+

        p = ptr_size
        # Offsets within the _type structure
        self.off_size = 0
        self.off_ptrdata = p
        self.off_hash = 2 * p
        self.off_tflag = 2 * p + 4
        self.off_align = 2 * p + 5
        self.off_field_align = 2 * p + 6
        self.off_kind = 2 * p + 7
        self.off_equal = 2 * p + 8
        self.off_gcdata = 3 * p + 8
        self.off_str = 4 * p + 8
        self.off_ptr_to_this = 4 * p + 12

        # Total base _type size
        self.base_size = 4 * p + 16

        # Uncommon type follows immediately after base _type
        # uncommonType: pkgPath(i32) + mcount(u16) + xcount(u16) + moff(u32) + _(u32)
        self.uncommon_size = 16


def _detect_type_layout(
    go_version_hint: str,
    ptr_size: int,
) -> _TypeLayout:
    """Create a _TypeLayout for the detected Go version."""
    relative = False
    if go_version_hint:
        m = re.search(r'(\d+)\.(\d+)', go_version_hint)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            if major >= 1 and minor >= 17:
                relative = True
    return _TypeLayout(ptr_size, relative_names=relative)


def _parse_single_type(
    data: bytes,
    type_off: int,
    layout: _TypeLayout,
    big_endian: bool = False,
) -> Optional[Dict[str, Any]]:
    """Parse a single runtime._type at the given file offset.

    Returns a dict with: name, kind, kind_name, size, tflag, has_uncommon,
    and the raw field values.
    """
    be = big_endian
    p = layout.ptr_size

    # Read base _type fields
    type_size = _read_ptr(data, type_off + layout.off_size, p, be)
    if type_size is None:
        return None

    kind_byte = _read_u8(data, type_off + layout.off_kind)
    if kind_byte is None:
        return None

    kind_val = kind_byte & 0x1F  # Lower 5 bits
    kind_name = _GO_KINDS.get(kind_val, f"unknown({kind_val})")

    tflag = _read_u8(data, type_off + layout.off_tflag)
    if tflag is None:
        tflag = 0

    has_uncommon = bool(tflag & _TFLAG_UNCOMMON)

    # Resolve type name
    str_off = _read_i32(data, type_off + layout.off_str, be)
    name = None
    if str_off is not None and str_off != 0:
        if layout.relative_names:
            name = _read_name_v117(data, type_off + layout.off_str, str_off)
        else:
            # Absolute offset from start of rodata or type section
            if str_off > 0 and str_off < len(data):
                name = _read_name(data, str_off)

    # Strip leading * if tflag indicates extra star
    if name and (tflag & _TFLAG_EXTRA_STAR) and name.startswith("*"):
        name = name[1:]

    return {
        "name": name or f"<anon_{hex(type_off)}>",
        "kind": kind_val,
        "kind_name": kind_name,
        "size": type_size,
        "tflag": tflag,
        "has_uncommon": has_uncommon,
        "_type_off": type_off,
        "_base_end": type_off + layout.base_size,
    }


def _parse_struct_fields(
    data: bytes,
    struct_data_off: int,
    layout: _TypeLayout,
    big_endian: bool = False,
) -> List[Dict[str, str]]:
    """Parse structType fields following the base _type.

    Go structType layout after _type:
        pkgPath (name offset, i32)
        fields slice: ptr(ptr_size) + len(ptr_size) + cap(ptr_size)

    Each structField:
        name (name offset, i32 relative in 1.17+, or ptr to name)
        typ (ptr to _type)
        offsetAnon (uintptr — offset in lower bits, exported flag in high bit)
    """
    be = big_endian
    p = layout.ptr_size

    # Skip pkgPath (i32)
    fields_off = struct_data_off + 4  # After pkgPath

    # Read fields slice header: ptr + len + cap (all ptr-sized)
    fields_ptr = _read_ptr(data, fields_off, p, be)
    fields_len = _read_ptr(data, fields_off + p, p, be)
    if fields_ptr is None or fields_len is None:
        return []

    fields_len = min(fields_len, _MAX_FIELDS_PER_STRUCT)
    if fields_len <= 0:
        return []

    # In Go 1.17+, the fields pointer may be relative (module-data-based).
    # For simplicity with file-based parsing, we try to interpret the pointer
    # as both absolute and relative to find valid data.

    # structField size: name(i32) + typ(ptr) + offsetAnon(ptr) for Go 1.17+
    # Or: name(ptr) + typ(ptr) + offsetAnon(ptr) for Go < 1.17
    if layout.relative_names:
        field_entry_size = 4 + p + p  # name_off(i32) + typ(ptr) + offset(ptr)
    else:
        field_entry_size = p + p + p  # name(ptr) + typ(ptr) + offset(ptr)

    fields = []
    for i in range(fields_len):
        entry_off = struct_data_off + 4 + 3 * p + i * field_entry_size
        if entry_off + field_entry_size > len(data):
            break

        # Read field name
        if layout.relative_names:
            name_off_rel = _read_i32(data, entry_off, be)
            if name_off_rel and name_off_rel != 0:
                fname = _read_name_v117(data, entry_off, name_off_rel)
            else:
                fname = None
            typ_off = entry_off + 4
        else:
            name_ptr = _read_ptr(data, entry_off, p, be)
            if name_ptr and 0 < name_ptr < len(data):
                fname = _read_name(data, name_ptr)
            else:
                fname = None
            typ_off = entry_off + p

        # Read type pointer (we just note the address, not recursively parse)
        typ_ptr = _read_ptr(data, typ_off, p, be)

        # Read offset+anon field
        offset_anon = _read_ptr(data, typ_off + p, p, be)
        if offset_anon is not None:
            field_offset = offset_anon >> 1  # Lower bits contain the offset
            is_embedded = bool(offset_anon & 1)
        else:
            field_offset = 0
            is_embedded = False

        field = {
            "name": fname or f"field_{i}",
            "offset": field_offset,
        }
        if is_embedded:
            field["embedded"] = True
        if typ_ptr:
            field["type_addr"] = hex(typ_ptr)

        fields.append(field)

    return fields


def _parse_interface_methods(
    data: bytes,
    iface_data_off: int,
    layout: _TypeLayout,
    big_endian: bool = False,
) -> List[Dict[str, str]]:
    """Parse interfaceType methods following the base _type.

    Go interfaceType layout after _type:
        pkgPath (name offset)
        methods slice: ptr(ptr_size) + len(ptr_size) + cap(ptr_size)

    Each imethod:
        name (name offset, i32)
        ityp (type offset, i32)
    """
    be = big_endian
    p = layout.ptr_size

    # Skip pkgPath
    methods_off = iface_data_off + 4

    # Read methods slice header
    methods_ptr = _read_ptr(data, methods_off, p, be)
    methods_len = _read_ptr(data, methods_off + p, p, be)
    if methods_ptr is None or methods_len is None:
        return []

    methods_len = min(methods_len, _MAX_METHODS_PER_INTERFACE)
    if methods_len <= 0:
        return []

    # Each imethod is 8 bytes: name_off(i32) + ityp(i32)
    imethod_size = 8
    methods = []
    for i in range(methods_len):
        entry_off = iface_data_off + 4 + 3 * p + i * imethod_size
        if entry_off + imethod_size > len(data):
            break

        name_off_rel = _read_i32(data, entry_off, be)
        mname = None
        if name_off_rel and name_off_rel != 0:
            if layout.relative_names:
                mname = _read_name_v117(data, entry_off, name_off_rel)
            elif 0 < name_off_rel < len(data):
                mname = _read_name(data, name_off_rel)

        methods.append({
            "name": mname or f"method_{i}",
            "index": i,
        })

    return methods


# ---------------------------------------------------------------------------
# Itab parsing
# ---------------------------------------------------------------------------

def _parse_itabs(
    data: bytes,
    itab_section: Dict[str, Any],
    layout: _TypeLayout,
    big_endian: bool = False,
    type_name_cache: Optional[Dict[int, str]] = None,
) -> List[Dict[str, Any]]:
    """Parse interface dispatch tables from .go.itab / .itablink section.

    Each itab is a fixed-size structure:
        inter (ptr)  — pointer to interfacetype
        _type (ptr)  — pointer to concrete type
        hash  (u32)  — copy of _type.hash
        _     (u32)  — padding
        fun[0] (ptr) — first method pointer (0 = unresolved)
    """
    be = big_endian
    p = layout.ptr_size

    sec_data = _get_section_data(data, itab_section)
    if not sec_data:
        return []

    # Itab minimum size: inter(ptr) + _type(ptr) + hash(4) + pad(4) + fun(ptr)
    itab_min_size = 2 * p + 8 + p
    sec_vaddr = itab_section.get("vaddr", 0)

    itabs = []
    off = 0
    while off + itab_min_size <= len(sec_data) and len(itabs) < _MAX_ITABS:
        inter_ptr = _read_ptr(sec_data, off, p, be)
        type_ptr = _read_ptr(sec_data, off + p, p, be)
        hash_val = _read_u32(sec_data, off + 2 * p, be)

        if inter_ptr is None or type_ptr is None:
            off += p  # Align and try next
            continue

        # Skip null entries
        if inter_ptr == 0 and type_ptr == 0:
            off += itab_min_size
            continue

        itab_entry = {
            "address": hex(sec_vaddr + off) if sec_vaddr else hex(off),
            "interface_addr": hex(inter_ptr),
            "concrete_type_addr": hex(type_ptr),
        }

        if hash_val is not None:
            itab_entry["type_hash"] = hex(hash_val)

        # Resolve names from cache if available
        if type_name_cache:
            if inter_ptr in type_name_cache:
                itab_entry["interface"] = type_name_cache[inter_ptr]
            if type_ptr in type_name_cache:
                itab_entry["concrete_type"] = type_name_cache[type_ptr]

        itabs.append(itab_entry)
        off += itab_min_size

    return itabs


# ---------------------------------------------------------------------------
# Typelink-based type enumeration
# ---------------------------------------------------------------------------

def _parse_typelinks(
    data: bytes,
    typelink_section: Dict[str, Any],
    rodata_section: Optional[Dict[str, Any]],
    layout: _TypeLayout,
    big_endian: bool = False,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """Walk the typelink section to enumerate all types.

    The typelink section contains int32 offsets from the beginning of the
    types/rodata section to each type descriptor.

    Returns: (types, structs, interfaces, errors)
    """
    be = big_endian
    sec_data = _get_section_data(data, typelink_section)
    if not sec_data:
        return [], [], [], ["Could not read typelink section data"]

    # Determine the base for type offsets
    # In Go, typelink offsets are relative to the module's types pointer,
    # which typically points to the start of rodata or a similar section.
    rodata_off = 0
    if rodata_section:
        rodata_off = rodata_section.get("offset", 0)

    types = []
    structs = []
    interfaces = []
    errors = []

    # Typelink contains int32 offsets
    n_entries = len(sec_data) // 4
    n_entries = min(n_entries, _MAX_TYPES)

    for i in range(n_entries):
        type_offset_rel = _read_i32(sec_data, i * 4, be)
        if type_offset_rel is None or type_offset_rel == 0:
            continue

        # Convert relative offset to absolute file offset
        type_off = rodata_off + type_offset_rel
        if type_off < 0 or type_off + layout.base_size > len(data):
            continue

        parsed = _parse_single_type(data, type_off, layout, be)
        if parsed is None:
            continue

        # Validate: kind must be in range
        if parsed["kind"] > 26:
            continue

        type_entry = {
            "name": parsed["name"],
            "kind": parsed["kind_name"],
            "size": parsed["size"],
        }

        # Parse struct fields
        if parsed["kind"] == 25:  # struct
            struct_extra_off = parsed["_base_end"]
            if parsed["has_uncommon"]:
                struct_extra_off += layout.uncommon_size
            fields = _parse_struct_fields(data, struct_extra_off, layout, be)
            if fields:
                struct_entry = dict(type_entry)
                struct_entry["fields"] = fields
                struct_entry["field_count"] = len(fields)
                structs.append(struct_entry)
            else:
                type_entry["field_count"] = 0
                types.append(type_entry)
            continue

        # Parse interface methods
        if parsed["kind"] == 20:  # interface
            iface_extra_off = parsed["_base_end"]
            if parsed["has_uncommon"]:
                iface_extra_off += layout.uncommon_size
            methods = _parse_interface_methods(data, iface_extra_off, layout, be)
            if methods:
                iface_entry = dict(type_entry)
                iface_entry["methods"] = methods
                iface_entry["method_count"] = len(methods)
                interfaces.append(iface_entry)
            else:
                type_entry["method_count"] = 0
                types.append(type_entry)
            continue

        types.append(type_entry)

    return types, structs, interfaces, errors


# ---------------------------------------------------------------------------
# Main API
# ---------------------------------------------------------------------------

def parse_go_types(
    file_data: bytes,
    sections: Optional[List[Dict[str, Any]]] = None,
    go_version_hint: str = "",
    ptr_size: int = 8,
    big_endian: bool = False,
) -> Optional[Dict[str, Any]]:
    """Parse Go runtime type descriptors from binary data.

    Args:
        file_data: Raw bytes of the Go binary.
        sections: List of section dicts (name, offset, size, vaddr).
            Required for locating typelink and itab sections.
        go_version_hint: Go version string (e.g. 'go1.21.5') to
            determine layout version.
        ptr_size: Pointer size in bytes (4 or 8).
        big_endian: Whether the binary is big-endian.

    Returns:
        Dict with types, structs, interfaces, itabs, and metadata,
        or None if no type metadata could be found.
    """
    if not file_data or not sections:
        return None

    layout = _detect_type_layout(go_version_hint, ptr_size)
    errors: List[str] = []

    # Locate sections
    typelink_sec = _find_section(sections, _TYPELINK_SECTION_NAMES)
    itab_sec = _find_section(sections, _ITAB_SECTION_NAMES)
    rodata_sec = _find_section(sections, _RODATA_SECTION_NAMES)

    if typelink_sec is None and itab_sec is None:
        return None  # No type metadata sections found

    types: List[Dict[str, Any]] = []
    structs: List[Dict[str, Any]] = []
    interfaces: List[Dict[str, Any]] = []
    itabs: List[Dict[str, Any]] = []

    # Parse types via typelink
    if typelink_sec:
        t, s, i, errs = _parse_typelinks(
            file_data, typelink_sec, rodata_sec, layout, big_endian,
        )
        types.extend(t)
        structs.extend(s)
        interfaces.extend(i)
        errors.extend(errs)

    # Build name cache for itab resolution
    type_name_cache: Dict[int, str] = {}
    # We can't directly map addresses to names without section vaddrs,
    # but populate from parsed types where possible

    # Parse itabs
    if itab_sec:
        itabs = _parse_itabs(
            file_data, itab_sec, layout, big_endian, type_name_cache,
        )

    if not types and not structs and not interfaces and not itabs:
        return None

    # Extract package names from type names
    packages = set()
    for t in types + structs + interfaces:
        name = t.get("name", "")
        if "." in name and not name.startswith("<"):
            pkg = name.rsplit(".", 1)[0]
            if pkg:
                packages.add(pkg)

    result = {
        "type_count": len(types) + len(structs) + len(interfaces),
        "struct_count": len(structs),
        "interface_count": len(interfaces),
        "itab_count": len(itabs),
    }

    if types:
        result["types"] = types[:_MAX_TYPES]
    if structs:
        result["structs"] = structs[:_MAX_TYPES]
    if interfaces:
        result["interfaces"] = interfaces[:_MAX_TYPES]
    if itabs:
        result["itabs"] = itabs[:_MAX_ITABS]
    if packages:
        result["type_packages"] = sorted(packages)[:200]
    if errors:
        result["parse_errors"] = errors[:20]

    return result
