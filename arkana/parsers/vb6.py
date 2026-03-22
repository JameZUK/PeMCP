"""Pure-struct VB6 PE header parser — no external dependencies.

Parses the Visual Basic 5/6 runtime header embedded in VB6-compiled PE files,
extracting project metadata, form/module objects, and external API declarations.

VB6 PE entry point pattern:
    68 xx xx xx xx    PUSH VBHeaderVA
    FF 15 xx xx xx xx CALL [ThunRTMain]

VB Header (120 bytes) at PUSH target starts with "VB5!" magic.
"""

import struct
from typing import Dict, Any, List, Optional, Tuple

# -- Constants ---------------------------------------------------------------

VB5_SIGNATURE = b"VB5!"
_VB_HEADER_SIZE = 120      # minimum VB header struct
_OBJECT_DESC_SIZE = 48     # COM object descriptor
_EXTERNAL_ENTRY_SIZE = 8   # external table entry (dll_name_ptr + func_name_ptr)
_MAX_OBJECTS = 1000        # safety cap
_MAX_EXTERNALS = 10000     # safety cap
_MAX_CSTRING = 256         # bounded string reads


# -- Helpers -----------------------------------------------------------------

def _va_to_offset(va: int, image_base: int, sections: List[Dict[str, Any]]) -> Optional[int]:
    """Convert a VA to file offset using PE section table.

    Args:
        va: Virtual address to convert.
        image_base: PE ImageBase.
        sections: List of dicts with 'virtual_address', 'virtual_size',
                  'pointer_to_raw_data', 'size_of_raw_data' keys.

    Returns:
        File offset, or None if the VA doesn't fall in any section.
    """
    rva = va - image_base
    if rva < 0:
        return None
    for sec in sections:
        sec_va = sec.get("virtual_address", 0)
        sec_vs = sec.get("virtual_size", 0)
        sec_ptr = sec.get("pointer_to_raw_data", 0)
        sec_rs = sec.get("size_of_raw_data", 0)
        if sec_va <= rva < sec_va + max(sec_vs, sec_rs):
            offset = sec_ptr + (rva - sec_va)
            if offset < 0:
                return None
            return offset
    return None


def _read_cstring(data: bytes, offset: int, max_len: int = _MAX_CSTRING) -> str:
    """Read a null-terminated string from data at offset, bounded by max_len.

    Returns empty string on any error.
    """
    if offset < 0 or offset >= len(data):
        return ""
    end = min(offset + max_len, len(data))
    chunk = data[offset:end]
    null_pos = chunk.find(b'\x00')
    if null_pos == -1:
        raw = chunk
    else:
        raw = chunk[:null_pos]
    try:
        return raw.decode("ascii", errors="replace")
    except Exception:
        return ""


# -- Detection ---------------------------------------------------------------

def is_vb6_binary(data: bytes, entry_point_offset: int) -> bool:
    """Quick check: does the PE entry point match the VB6 startup pattern?

    Looks for PUSH imm32 (68h) at entry point, then validates "VB5!" signature
    at the target address.  Does NOT require full section table — just raw data
    and the file offset of the entry point.

    Args:
        data: Raw PE file bytes.
        entry_point_offset: File offset of AddressOfEntryPoint.

    Returns:
        True if VB6 startup pattern detected.
    """
    if entry_point_offset < 0 or entry_point_offset + 6 > len(data):
        return False
    # Check for PUSH imm32 opcode
    if data[entry_point_offset] != 0x68:
        return False
    # The pushed value is a VA pointing to the VB header.
    # We need the image base and sections to convert, but for a quick check
    # we can scan forward from the entry point for "VB5!" in a reasonable window.
    # However, a more reliable approach: read the DOS/PE headers to get ImageBase.
    try:
        if len(data) < 0x40:
            return False
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 0x58 > len(data):
            return False
        pe_sig = data[e_lfanew:e_lfanew + 4]
        if pe_sig != b"PE\x00\x00":
            return False
        # Optional header offset
        opt_off = e_lfanew + 0x18
        magic = struct.unpack_from("<H", data, opt_off)[0]
        if magic == 0x10b:  # PE32
            image_base = struct.unpack_from("<I", data, opt_off + 28)[0]
        elif magic == 0x20b:  # PE32+
            image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
        else:
            return False

        # Parse section table for VA→offset conversion
        coff_off = e_lfanew + 4
        num_sections = struct.unpack_from("<H", data, coff_off + 2)[0]
        size_opt = struct.unpack_from("<H", data, coff_off + 16)[0]
        sec_table_off = opt_off + size_opt
        sections = []
        for i in range(min(num_sections, 96)):
            s_off = sec_table_off + i * 40
            if s_off + 40 > len(data):
                break
            sec_vs = struct.unpack_from("<I", data, s_off + 8)[0]
            sec_va = struct.unpack_from("<I", data, s_off + 12)[0]
            sec_rs = struct.unpack_from("<I", data, s_off + 16)[0]
            sec_ptr = struct.unpack_from("<I", data, s_off + 20)[0]
            sections.append({
                "virtual_address": sec_va,
                "virtual_size": sec_vs,
                "pointer_to_raw_data": sec_ptr,
                "size_of_raw_data": sec_rs,
            })

        # Read PUSH operand (VA of VB header)
        vb_header_va = struct.unpack_from("<I", data, entry_point_offset + 1)[0]
        vb_header_off = _va_to_offset(vb_header_va, image_base, sections)
        if vb_header_off is None or vb_header_off + 4 > len(data):
            return False
        return data[vb_header_off:vb_header_off + 4] == VB5_SIGNATURE
    except (struct.error, IndexError, ValueError):
        return False


# -- Full Parser -------------------------------------------------------------

def parse_vb6_header(
    data: bytes,
    image_base: int,
    sections: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Parse the VB6 header, object table, and external table from a PE.

    Returns a structured dict with partial results on parse failures.

    Args:
        data: Raw PE file bytes.
        image_base: PE ImageBase value.
        sections: List of section dicts (virtual_address, virtual_size,
                  pointer_to_raw_data, size_of_raw_data).

    Returns:
        Dict with keys: signature, project_name, project_description, guid,
        language_id, form_count, module_count, objects, externals,
        parse_errors (list of non-fatal issues).
    """
    result: Dict[str, Any] = {
        "signature": None,
        "project_name": "",
        "project_description": "",
        "guid": "",
        "language_id": 0,
        "form_count": 0,
        "module_count": 0,
        "objects": [],
        "externals": [],
        "parse_errors": [],
    }

    # --- Find VB header via entry point ---
    ep_offset = _find_entry_point_offset(data)
    if ep_offset is None:
        result["parse_errors"].append("Could not locate PE entry point")
        return result

    if ep_offset + 6 > len(data) or data[ep_offset] != 0x68:
        result["parse_errors"].append("Entry point does not start with PUSH imm32")
        return result

    vb_header_va = struct.unpack_from("<I", data, ep_offset + 1)[0]
    vb_header_off = _va_to_offset(vb_header_va, image_base, sections)
    if vb_header_off is None:
        result["parse_errors"].append(f"VB header VA 0x{vb_header_va:08X} not in any section")
        return result

    # --- Parse VB Header (120 bytes) ---
    if vb_header_off + _VB_HEADER_SIZE > len(data):
        result["parse_errors"].append("VB header truncated")
        return result

    sig = data[vb_header_off:vb_header_off + 4]
    if sig != VB5_SIGNATURE:
        result["parse_errors"].append(f"Bad VB signature: {sig!r}")
        return result
    result["signature"] = sig.decode("ascii")

    try:
        # VB Header layout (key offsets):
        #  +0x00: "VB5!" signature (4 bytes)
        #  +0x04: runtime version (2 bytes)
        #  +0x06: language DLL (14 bytes, null-terminated)
        #  +0x14: backup language DLL (14 bytes)
        #  +0x22: runtime DLL version (2 bytes)
        #  +0x24: language ID (4 bytes, LCID)
        #  +0x28: backup language ID (4 bytes)
        #  +0x2C: sub-main pointer (4 bytes VA)
        #  +0x30: project info pointer (4 bytes VA)
        #  +0x34: controls used / forms present (4 bytes)
        #  +0x38: controls used 2 (4 bytes)
        #  +0x3C: thread flags (4 bytes)
        #  +0x40: thread count (4 bytes)
        #  +0x44: form count (2 bytes)
        #  +0x46: external count (2 bytes)
        #  +0x48: thunk count (4 bytes)
        #  +0x4C: GUI table VA (4 bytes)
        #  +0x50: external table VA (4 bytes)
        #  +0x54: COM object table VA (4 bytes)
        #  +0x58: project exe name offset (4 bytes, relative from header)
        #  +0x5C: project title offset (4 bytes, relative from header)
        #  +0x60: help file offset (4 bytes)
        #  +0x64: project name offset (4 bytes, relative from header)

        # Initialise before try block so they are always defined even if
        # a struct.error is raised before the assignments below.
        ext_count = 0
        ext_table_va = 0
        obj_table_va = 0

        lang_id = struct.unpack_from("<I", data, vb_header_off + 0x24)[0]
        result["language_id"] = lang_id

        form_count = struct.unpack_from("<H", data, vb_header_off + 0x44)[0]
        ext_count = struct.unpack_from("<H", data, vb_header_off + 0x46)[0]
        result["form_count"] = form_count
        result["module_count"] = 0  # filled from object table below

        ext_table_va = struct.unpack_from("<I", data, vb_header_off + 0x50)[0]
        obj_table_va = struct.unpack_from("<I", data, vb_header_off + 0x54)[0]

        # Project exe name (offset relative to VB header start)
        exe_name_rel = struct.unpack_from("<I", data, vb_header_off + 0x58)[0]
        if exe_name_rel and exe_name_rel < 0x10000:
            result["project_exe_name"] = _read_cstring(data, vb_header_off + exe_name_rel)

        # Project title (offset relative to VB header start)
        title_rel = struct.unpack_from("<I", data, vb_header_off + 0x5C)[0]
        if title_rel and title_rel < 0x10000:
            result["project_name"] = _read_cstring(data, vb_header_off + title_rel)

        # Project description (at +0x64, relative to header)
        desc_rel = struct.unpack_from("<I", data, vb_header_off + 0x64)[0]
        if desc_rel and desc_rel < 0x10000:
            result["project_description"] = _read_cstring(data, vb_header_off + desc_rel)

        # --- Parse GUID from project info ---
        proj_info_va = struct.unpack_from("<I", data, vb_header_off + 0x30)[0]
        if proj_info_va:
            _parse_project_info(data, proj_info_va, image_base, sections, result)

    except (struct.error, IndexError) as exc:
        result["parse_errors"].append(f"VB header field parse error: {exc}")

    # --- Parse Object Table ---
    if obj_table_va:
        _parse_object_table(data, obj_table_va, image_base, sections, result)

    # --- Parse External Table ---
    if ext_table_va and ext_count:
        _parse_external_table(data, ext_table_va, ext_count, image_base, sections, result)

    return result


# -- Internal helpers --------------------------------------------------------

def _find_entry_point_offset(data: bytes) -> Optional[int]:
    """Locate PE entry point file offset from raw PE data."""
    try:
        if len(data) < 0x40:
            return None
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 0x58 > len(data):
            return None
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        opt_off = e_lfanew + 0x18
        magic = struct.unpack_from("<H", data, opt_off)[0]
        if magic == 0x10b:  # PE32
            ep_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
        elif magic == 0x20b:  # PE32+
            ep_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
        else:
            return None

        # Build sections
        coff_off = e_lfanew + 4
        num_sections = struct.unpack_from("<H", data, coff_off + 2)[0]
        size_opt = struct.unpack_from("<H", data, coff_off + 16)[0]
        sec_table_off = opt_off + size_opt

        for i in range(min(num_sections, 96)):
            s_off = sec_table_off + i * 40
            if s_off + 40 > len(data):
                break
            sec_vs = struct.unpack_from("<I", data, s_off + 8)[0]
            sec_va = struct.unpack_from("<I", data, s_off + 12)[0]
            sec_rs = struct.unpack_from("<I", data, s_off + 16)[0]
            sec_ptr = struct.unpack_from("<I", data, s_off + 20)[0]
            if sec_va <= ep_rva < sec_va + max(sec_vs, sec_rs):
                return sec_ptr + (ep_rva - sec_va)
        return None
    except (struct.error, IndexError, ValueError):
        return None


def _parse_project_info(
    data: bytes,
    proj_info_va: int,
    image_base: int,
    sections: List[Dict[str, Any]],
    result: Dict[str, Any],
) -> None:
    """Parse the VB Project Info structure for the GUID."""
    off = _va_to_offset(proj_info_va, image_base, sections)
    if off is None or off + 0x30 > len(data):
        return
    try:
        # GUID is at +0x04 in the ProjectInfo struct (16 bytes)
        guid_off = off + 0x04
        if guid_off + 16 > len(data):
            return
        d1, d2, d3 = struct.unpack_from("<IHH", data, guid_off)
        d4 = data[guid_off + 8:guid_off + 16]
        result["guid"] = (
            f"{{{d1:08X}-{d2:04X}-{d3:04X}-"
            f"{d4[0]:02X}{d4[1]:02X}-"
            f"{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}}}"
        )
    except (struct.error, IndexError):
        result["parse_errors"].append("Failed to parse project GUID")


def _parse_object_table(
    data: bytes,
    obj_table_va: int,
    image_base: int,
    sections: List[Dict[str, Any]],
    result: Dict[str, Any],
) -> None:
    """Parse the VB COM Object Table.

    Object Table header (at obj_table_va):
      +0x00: null pointer (4 bytes)
      +0x04: exec-proj VA (4 bytes)
      +0x08: project info2 VA (4 bytes)
      +0x0C: reserved (4 bytes)
      +0x10: project object count (4 bytes)  <-- number of objects
      +0x14: padding (variable)
    Then object descriptors follow after the header.

    Each Object Descriptor is 48 bytes:
      +0x00: object info VA (4 bytes)
      +0x04: reserved (4 bytes)
      +0x08: public bytes VA (4 bytes)
      +0x0C: static bytes VA (4 bytes)
      +0x10: module public VA (4 bytes)
      +0x14: module static VA (4 bytes)
      +0x18: object name VA (4 bytes)
      +0x1C: method count (4 bytes)
      +0x20: methods VA (4 bytes)
      +0x24: object type (2 bytes)  — 0x02=Module, 0x08=Form, 0x10=Class
      +0x26: padding (2 bytes)
      +0x28: null (8 bytes)
    """
    tbl_off = _va_to_offset(obj_table_va, image_base, sections)
    if tbl_off is None:
        result["parse_errors"].append("Object table VA not in any section")
        return

    # Read object count from table header
    if tbl_off + 0x14 > len(data):
        result["parse_errors"].append("Object table header truncated")
        return

    try:
        obj_count = struct.unpack_from("<I", data, tbl_off + 0x10)[0]
    except struct.error:
        result["parse_errors"].append("Failed to read object count")
        return

    # Reject obviously bogus counts early (typical VB6 apps have <50 objects)
    if obj_count > 500:
        result["parse_errors"].append(
            f"Object count {obj_count} exceeds reasonable limit (500), likely corrupt header"
        )
        obj_count = 0
    obj_count = min(obj_count, _MAX_OBJECTS)

    # Object descriptors start after a fixed header.
    # The header size varies by VB version, but commonly 0x38 (56) bytes.
    # We probe both 0x38 and 0x14 and pick whichever yields a valid first descriptor.
    _KNOWN_TYPES = {0x02, 0x08, 0x10, 0x20}
    type_map = {0x02: "Module", 0x08: "Form", 0x10: "Class", 0x20: "UserControl"}

    def _probe_descriptor(start: int) -> bool:
        """Check if the first object descriptor at `start` looks valid."""
        if start + _OBJECT_DESC_SIZE > len(data):
            return False
        try:
            probe_name_va = struct.unpack_from("<I", data, start + 0x18)[0]
            probe_type = struct.unpack_from("<H", data, start + 0x24)[0]
        except struct.error:
            return False
        # name_va should be 0 or a plausible VA (within image range)
        if probe_name_va != 0:
            probe_off = _va_to_offset(probe_name_va, image_base, sections)
            if probe_off is None:
                return False
        return probe_type in _KNOWN_TYPES

    objects: List[Dict[str, Any]] = []
    module_count = 0

    desc_start = tbl_off + 0x38  # common header size
    if obj_count > 0 and not _probe_descriptor(desc_start):
        # Try alternative header size
        alt_start = tbl_off + 0x14
        if _probe_descriptor(alt_start):
            desc_start = alt_start
        else:
            result["parse_errors"].append(
                "Object descriptors not found at expected offsets (0x38 or 0x14)"
            )
            result["objects"] = []
            result["module_count"] = 0
            return

    for i in range(obj_count):
        d_off = desc_start + i * _OBJECT_DESC_SIZE
        if d_off + _OBJECT_DESC_SIZE > len(data):
            break
        try:
            name_va = struct.unpack_from("<I", data, d_off + 0x18)[0]
            method_count = struct.unpack_from("<I", data, d_off + 0x1C)[0]
            obj_type_raw = struct.unpack_from("<H", data, d_off + 0x24)[0]
        except struct.error:
            continue

        obj_type = type_map.get(obj_type_raw, f"Unknown(0x{obj_type_raw:02X})")

        name = ""
        if name_va:
            name_off = _va_to_offset(name_va, image_base, sections)
            if name_off is not None:
                name = _read_cstring(data, name_off)

        # Clamp method count to a sane range
        method_count = min(method_count, 10000)

        obj_info: Dict[str, Any] = {
            "name": name,
            "type": obj_type,
            "method_count": method_count,
        }
        objects.append(obj_info)
        if obj_type == "Module":
            module_count += 1

    result["objects"] = objects
    result["module_count"] = module_count


def _parse_external_table(
    data: bytes,
    ext_table_va: int,
    ext_count: int,
    image_base: int,
    sections: List[Dict[str, Any]],
    result: Dict[str, Any],
) -> None:
    """Parse the VB External Table (Declare Function entries).

    Each entry is 8 bytes:
      +0x00: type (4 bytes) — 0x06 = Declare Function
      +0x04: extern info VA (4 bytes) — points to struct with DLL name VA + func name VA

    The extern info struct (at the VA):
      +0x00: padding/type (variable)
      +0x04: DLL name VA (4 bytes)
      +0x08: function name VA (4 bytes)
    """
    tbl_off = _va_to_offset(ext_table_va, image_base, sections)
    if tbl_off is None:
        result["parse_errors"].append("External table VA not in any section")
        return

    ext_count = min(ext_count, _MAX_EXTERNALS)
    externals: List[Dict[str, str]] = []

    for i in range(ext_count):
        e_off = tbl_off + i * _EXTERNAL_ENTRY_SIZE
        if e_off + _EXTERNAL_ENTRY_SIZE > len(data):
            break
        try:
            struct.unpack_from("<I", data, e_off)  # skip type field
            info_va = struct.unpack_from("<I", data, e_off + 4)[0]
        except struct.error:
            continue

        if not info_va:
            continue

        info_off = _va_to_offset(info_va, image_base, sections)
        if info_off is None or info_off + 0x0C > len(data):
            continue

        try:
            dll_name_va = struct.unpack_from("<I", data, info_off + 0x04)[0]
            func_name_va = struct.unpack_from("<I", data, info_off + 0x08)[0]
        except struct.error:
            continue

        dll_name = ""
        func_name = ""
        if dll_name_va:
            dll_off = _va_to_offset(dll_name_va, image_base, sections)
            if dll_off is not None:
                dll_name = _read_cstring(data, dll_off)
        if func_name_va:
            func_off = _va_to_offset(func_name_va, image_base, sections)
            if func_off is not None:
                func_name = _read_cstring(data, func_off)

        if dll_name or func_name:
            externals.append({
                "dll": dll_name,
                "function": func_name,
            })

    result["externals"] = externals
