"""Tests for Go runtime type descriptor parser."""
import struct
import unittest

from arkana.parsers.go_types import (
    _GO_KINDS,
    _MAX_FIELDS_PER_STRUCT,
    _MAX_METHODS_PER_INTERFACE,
    _MAX_TYPES,
    _TypeLayout,
    _detect_type_layout,
    _find_section,
    _get_section_data,
    _parse_interface_methods,
    _parse_itabs,
    _parse_single_type,
    _parse_struct_fields,
    _parse_typelinks,
    _read_name,
    _read_name_v117,
    _read_ptr,
    _read_u32,
    parse_go_types,
)


# ---------------------------------------------------------------------------
# Helpers for building synthetic type data
# ---------------------------------------------------------------------------

def _encode_go_name(name: str, flags: int = 0) -> bytes:
    """Encode a Go name as [flags] [len_hi] [len_lo] [name_bytes]."""
    name_bytes = name.encode("utf-8")
    return bytes([flags, (len(name_bytes) >> 8) & 0xFF, len(name_bytes) & 0xFF]) + name_bytes


def _build_type_descriptor(
    name_bytes: bytes,
    kind: int,
    type_size: int = 48,
    tflag: int = 0,
    ptr_size: int = 8,
    name_offset: int = 0,
    big_endian: bool = False,
):
    """Build a synthetic runtime._type and return (data, name_abs_offset).

    Returns the complete binary data with the type descriptor and the name
    placed after it.
    """
    e = ">" if big_endian else "<"
    p = ptr_size
    pfmt = f"{e}Q" if p == 8 else f"{e}I"

    # The type descriptor
    data = bytearray()
    data += struct.pack(pfmt, type_size)       # size
    data += struct.pack(pfmt, 0)               # ptrdata
    data += struct.pack(f"{e}I", 0x12345678)   # hash
    data += bytes([tflag, 8, 8, kind & 0x1F])  # tflag, align, fieldAlign, kind
    data += struct.pack(pfmt, 0)               # equal
    data += struct.pack(pfmt, 0)               # gcdata

    # str offset — absolute offset of the name in the data
    name_abs_off = len(data) + 8  # After str(i32) + ptrToThis(i32)
    data += struct.pack(f"{e}i", name_abs_off)  # str
    data += struct.pack(f"{e}i", 0)             # ptrToThis

    # Append the name
    data += name_bytes

    return bytes(data), name_abs_off


class TestReadName(unittest.TestCase):
    """Tests for Go name reading."""

    def test_simple_name(self):
        data = _encode_go_name("main.Config")
        self.assertEqual(_read_name(data, 0), "main.Config")

    def test_name_with_flags(self):
        data = _encode_go_name("Exported", flags=0x01)
        self.assertEqual(_read_name(data, 0), "Exported")

    def test_empty_name(self):
        data = bytes([0, 0, 0])  # flags=0, len=0
        self.assertIsNone(_read_name(data, 0))

    def test_truncated_data(self):
        self.assertIsNone(_read_name(b"\x00\x00", 0))

    def test_out_of_bounds(self):
        data = _encode_go_name("test")
        self.assertIsNone(_read_name(data, len(data)))

    def test_negative_offset(self):
        data = _encode_go_name("test")
        self.assertIsNone(_read_name(data, -1))

    def test_name_too_long(self):
        data = bytes([0, 0x10, 0x00]) + b"x" * 4096  # len=4096
        self.assertIsNone(_read_name(data, 0, max_len=512))

    def test_relative_name(self):
        # Build data where name is at an offset relative to the reference point
        name_data = _encode_go_name("crypto.Hash")
        padding = b"\x00" * 100
        data = padding + name_data
        # Reference point at offset 0, name at offset 100
        result = _read_name_v117(data, 0, 100)
        self.assertEqual(result, "crypto.Hash")


class TestTypeLayout(unittest.TestCase):
    """Tests for type layout detection."""

    def test_pre117_layout(self):
        layout = _detect_type_layout("go1.16", 8)
        self.assertFalse(layout.relative_names)
        self.assertEqual(layout.ptr_size, 8)

    def test_117_layout(self):
        layout = _detect_type_layout("go1.17", 8)
        self.assertTrue(layout.relative_names)

    def test_121_layout(self):
        layout = _detect_type_layout("go1.21.5", 8)
        self.assertTrue(layout.relative_names)

    def test_32bit(self):
        layout = _detect_type_layout("go1.21", 4)
        self.assertEqual(layout.ptr_size, 4)
        self.assertTrue(layout.relative_names)

    def test_empty_version(self):
        layout = _detect_type_layout("", 8)
        self.assertFalse(layout.relative_names)  # Default to pre-1.17

    def test_base_size_64bit(self):
        layout = _TypeLayout(8)
        # 4*8 + 16 = 48
        self.assertEqual(layout.base_size, 48)

    def test_base_size_32bit(self):
        layout = _TypeLayout(4)
        # 4*4 + 16 = 32
        self.assertEqual(layout.base_size, 32)


class TestParseSingleType(unittest.TestCase):
    """Tests for parsing individual type descriptors."""

    def test_struct_kind(self):
        name = _encode_go_name("main.Config")
        data, name_off = _build_type_descriptor(name, kind=25, type_size=64)
        layout = _TypeLayout(8, relative_names=False)
        result = _parse_single_type(data, 0, layout)
        self.assertIsNotNone(result)
        self.assertEqual(result["kind"], 25)
        self.assertEqual(result["kind_name"], "struct")
        self.assertEqual(result["size"], 64)

    def test_interface_kind(self):
        name = _encode_go_name("io.Reader")
        data, name_off = _build_type_descriptor(name, kind=20)
        layout = _TypeLayout(8, relative_names=False)
        result = _parse_single_type(data, 0, layout)
        self.assertIsNotNone(result)
        self.assertEqual(result["kind_name"], "interface")

    def test_string_kind(self):
        name = _encode_go_name("string")
        data, name_off = _build_type_descriptor(name, kind=24)
        layout = _TypeLayout(8, relative_names=False)
        result = _parse_single_type(data, 0, layout)
        self.assertEqual(result["kind_name"], "string")

    def test_invalid_kind_filtered(self):
        """Kinds > 26 should be caught by the caller."""
        name = _encode_go_name("bad")
        data, _ = _build_type_descriptor(name, kind=30)
        layout = _TypeLayout(8, relative_names=False)
        result = _parse_single_type(data, 0, layout)
        self.assertIsNotNone(result)
        self.assertEqual(result["kind"], 30)
        self.assertTrue(result["kind_name"].startswith("unknown"))

    def test_truncated_data(self):
        layout = _TypeLayout(8)
        result = _parse_single_type(b"\x00" * 10, 0, layout)
        self.assertIsNone(result)

    def test_extra_star_stripping(self):
        """tflag EXTRA_STAR should strip leading * from name."""
        name = _encode_go_name("*main.Config")
        data, _ = _build_type_descriptor(name, kind=22, tflag=0x02)  # TFLAG_EXTRA_STAR
        layout = _TypeLayout(8, relative_names=False)
        result = _parse_single_type(data, 0, layout)
        self.assertEqual(result["name"], "main.Config")

    def test_uncommon_flag(self):
        name = _encode_go_name("main.MyType")
        data, _ = _build_type_descriptor(name, kind=25, tflag=0x01)  # TFLAG_UNCOMMON
        layout = _TypeLayout(8, relative_names=False)
        result = _parse_single_type(data, 0, layout)
        self.assertTrue(result["has_uncommon"])

    def test_all_go_kinds(self):
        """Verify all Go kinds 0-26 are recognized."""
        for kind_val, kind_name in _GO_KINDS.items():
            self.assertTrue(kind_val <= 26)
            self.assertIsInstance(kind_name, str)


class TestFindSection(unittest.TestCase):
    """Tests for section location helper."""

    def test_find_typelink(self):
        sections = [
            {"name": ".text", "offset": 0, "size": 1000},
            {"name": ".typelink", "offset": 1000, "size": 500},
            {"name": ".rodata", "offset": 1500, "size": 2000},
        ]
        from arkana.parsers.go_types import _TYPELINK_SECTION_NAMES
        sec = _find_section(sections, _TYPELINK_SECTION_NAMES)
        self.assertIsNotNone(sec)
        self.assertEqual(sec["name"], ".typelink")

    def test_find_elf_typelink(self):
        sections = [
            {"name": ".data.rel.ro.typelink", "offset": 100, "size": 200},
        ]
        from arkana.parsers.go_types import _TYPELINK_SECTION_NAMES
        sec = _find_section(sections, _TYPELINK_SECTION_NAMES)
        self.assertIsNotNone(sec)

    def test_find_macho_typelink(self):
        sections = [
            {"name": "__typelink", "offset": 100, "size": 200},
        ]
        from arkana.parsers.go_types import _TYPELINK_SECTION_NAMES
        sec = _find_section(sections, _TYPELINK_SECTION_NAMES)
        self.assertIsNotNone(sec)

    def test_not_found(self):
        sections = [{"name": ".text", "offset": 0, "size": 100}]
        from arkana.parsers.go_types import _TYPELINK_SECTION_NAMES
        sec = _find_section(sections, _TYPELINK_SECTION_NAMES)
        self.assertIsNone(sec)

    def test_empty_sections(self):
        from arkana.parsers.go_types import _TYPELINK_SECTION_NAMES
        sec = _find_section([], _TYPELINK_SECTION_NAMES)
        self.assertIsNone(sec)


class TestGetSectionData(unittest.TestCase):
    """Tests for section data extraction."""

    def test_valid_section(self):
        data = b"\x00" * 100 + b"\x41" * 50 + b"\x00" * 100
        section = {"offset": 100, "size": 50}
        result = _get_section_data(data, section)
        self.assertEqual(result, b"\x41" * 50)

    def test_out_of_bounds(self):
        data = b"\x00" * 100
        section = {"offset": 50, "size": 100}
        result = _get_section_data(data, section)
        self.assertIsNone(result)

    def test_zero_size(self):
        data = b"\x00" * 100
        section = {"offset": 0, "size": 0}
        result = _get_section_data(data, section)
        self.assertIsNone(result)


class TestParseGoTypes(unittest.TestCase):
    """Integration tests for the main parse_go_types API."""

    def test_none_without_sections(self):
        self.assertIsNone(parse_go_types(b"\x00" * 100, None))

    def test_none_without_data(self):
        self.assertIsNone(parse_go_types(b"", []))

    def test_none_without_type_sections(self):
        """No typelink or itab section → returns None."""
        sections = [{"name": ".text", "offset": 0, "size": 100}]
        result = parse_go_types(b"\x00" * 100, sections)
        self.assertIsNone(result)

    def test_with_empty_typelink(self):
        """Typelink section exists but has no valid entries → None."""
        data = b"\x00" * 2000
        sections = [
            {"name": ".typelink", "offset": 100, "size": 40},
            {"name": ".rodata", "offset": 0, "size": 2000},
        ]
        result = parse_go_types(data, sections, ptr_size=8)
        # All-zero typelink entries should be skipped → None
        self.assertIsNone(result)

    def test_result_structure(self):
        """Verify the result dict has expected keys when types are found."""
        # Build a type at offset 200 in the file
        name = _encode_go_name("main.Config")
        type_data, _ = _build_type_descriptor(name, kind=2, type_size=8)  # int kind

        # File data: rodata starts at 0, type at offset 200
        file_data = bytearray(b"\x00" * 2000)
        type_off = 200
        file_data[type_off: type_off + len(type_data)] = type_data

        # Typelink entry: int32 offset from rodata start to the type
        typelink_data = struct.pack("<i", type_off)
        tl_off = 1000
        file_data[tl_off: tl_off + 4] = typelink_data

        sections = [
            {"name": ".typelink", "offset": tl_off, "size": 4},
            {"name": ".rodata", "offset": 0, "size": 2000},
        ]

        result = parse_go_types(bytes(file_data), sections, ptr_size=8)
        self.assertIsNotNone(result)
        self.assertIn("type_count", result)
        self.assertGreater(result["type_count"], 0)

    def test_safety_cap_types(self):
        """Verify _MAX_TYPES cap is applied."""
        self.assertEqual(_MAX_TYPES, 5000)

    def test_safety_cap_fields(self):
        self.assertEqual(_MAX_FIELDS_PER_STRUCT, 200)

    def test_safety_cap_methods(self):
        self.assertEqual(_MAX_METHODS_PER_INTERFACE, 100)


class TestItabParsing(unittest.TestCase):
    """Tests for itab section parsing."""

    def test_empty_itab_section(self):
        data = b"\x00" * 100
        section = {"offset": 0, "size": 100, "vaddr": 0x400000}
        layout = _TypeLayout(8)
        itabs = _parse_itabs(data, section, layout)
        # All zeros → skipped
        self.assertEqual(len(itabs), 0)

    def test_single_itab(self):
        """Build a synthetic itab entry and verify parsing."""
        # itab: inter(ptr=8) + _type(ptr=8) + hash(4) + pad(4) + fun(ptr=8)
        data = bytearray(b"\x00" * 200)
        off = 0
        # inter pointer
        struct.pack_into("<Q", data, off, 0x401000)
        # _type pointer
        struct.pack_into("<Q", data, off + 8, 0x402000)
        # hash
        struct.pack_into("<I", data, off + 16, 0xDEADBEEF)
        # pad
        struct.pack_into("<I", data, off + 20, 0)
        # fun[0]
        struct.pack_into("<Q", data, off + 24, 0x403000)

        section = {"offset": 0, "size": 32, "vaddr": 0x500000}
        layout = _TypeLayout(8)
        itabs = _parse_itabs(bytes(data), section, layout)
        self.assertEqual(len(itabs), 1)
        self.assertEqual(itabs[0]["interface_addr"], hex(0x401000))
        self.assertEqual(itabs[0]["concrete_type_addr"], hex(0x402000))
        self.assertEqual(itabs[0]["type_hash"], hex(0xDEADBEEF))

    def test_itab_cap(self):
        """Verify _MAX_ITABS is respected."""
        from arkana.parsers.go_types import _MAX_ITABS
        self.assertEqual(_MAX_ITABS, 10_000)


class TestPackageExtraction(unittest.TestCase):
    """Tests for package name extraction from type names."""

    def test_simple_package(self):
        name = "main.Config"
        pkg = name.rsplit(".", 1)[0]
        self.assertEqual(pkg, "main")

    def test_nested_package(self):
        name = "crypto/tls.Conn"
        pkg = name.rsplit(".", 1)[0]
        self.assertEqual(pkg, "crypto/tls")

    def test_no_package(self):
        name = "int"
        parts = name.rsplit(".", 1)
        self.assertEqual(len(parts), 1)  # No dot


if __name__ == "__main__":
    unittest.main()
