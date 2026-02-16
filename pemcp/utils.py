"""Utility functions for PE analysis output and formatting."""
import datetime
import math
import re
import sys

from typing import Dict, Any, Optional, List

from pemcp.config import pefile

# --- ReDoS Protection ---
_MAX_REGEX_PATTERN_LENGTH = 1000
# Detects nested quantifiers that can cause catastrophic backtracking.
# Matches patterns like (X+)+, (X*)+, (X+)*, (X{n,m})+ etc.
_NESTED_QUANTIFIER_RE = re.compile(
    r'\([^)]*[+*}\?][^)]*\)\s*[+*{]'
)


def validate_regex_pattern(pattern: str) -> None:
    """Validate a regex pattern for safety before compilation.

    Raises ValueError if the pattern is too long, contains constructs
    that are known to cause catastrophic backtracking (ReDoS), or is
    not a valid regular expression.
    """
    if len(pattern) > _MAX_REGEX_PATTERN_LENGTH:
        raise ValueError(
            f"Regex pattern is too long ({len(pattern)} chars). "
            f"Maximum allowed length is {_MAX_REGEX_PATTERN_LENGTH} characters."
        )
    if _NESTED_QUANTIFIER_RE.search(pattern):
        raise ValueError(
            f"Regex pattern contains nested quantifiers which can cause "
            f"catastrophic backtracking (ReDoS). Please simplify the pattern: "
            f"'{pattern[:80]}{'...' if len(pattern) > 80 else ''}'"
        )
    # Verify the pattern actually compiles
    try:
        re.compile(pattern)
    except re.error as e:
        raise ValueError(f"Invalid regex pattern: {e}") from e


def shannon_entropy(data: bytes) -> float:
    """Compute the Shannon entropy of a byte sequence.

    Returns a value between 0.0 (uniform) and 8.0 (maximum randomness).
    Returns 0.0 for empty input.
    """
    length = len(data)
    if length == 0:
        return 0.0
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def safe_print(text_to_print, verbose_prefix=""):
    try:
        print(f"{verbose_prefix}{text_to_print}")
    except UnicodeEncodeError:
        try:
            output_encoding = sys.stdout.encoding if sys.stdout.encoding else 'utf-8'
            encoded_text = str(text_to_print).encode(output_encoding, errors='backslashreplace').decode(output_encoding, errors='ignore')
            print(f"{verbose_prefix}{encoded_text} (some characters replaced/escaped)")
        except Exception:
            print(f"{verbose_prefix}<Unencodable string: contains characters not supported by output encoding>")


def format_timestamp(timestamp_val: int) -> str:
    if not isinstance(timestamp_val, int) or timestamp_val < 0: return f"{timestamp_val} (Invalid timestamp value)"
    if timestamp_val == 0: return "0 (No timestamp or invalid)"
    current_year = datetime.datetime.now(datetime.timezone.utc).year
    try:
        dt_obj = datetime.datetime.fromtimestamp(timestamp_val, datetime.timezone.utc)
        formatted_date = dt_obj.strftime('%Y-%m-%d %H:%M:%S UTC')
        if dt_obj.year > current_year + 20 or dt_obj.year < 1980:
            return f"{formatted_date} ({timestamp_val}) (Timestamp unusual)"
        return formatted_date
    except (ValueError, OSError, OverflowError):
        return f"{timestamp_val} (Invalid or out-of-range timestamp value)"


def get_file_characteristics(flags: int) -> List[str]:
    characteristics = []
    for flag_name, flag_val in pefile.IMAGE_CHARACTERISTICS.items():
        if isinstance(flag_val, int) and (flags & flag_val): characteristics.append(flag_name)
    return characteristics if characteristics else ["NONE"]


def get_dll_characteristics(flags: int) -> List[str]:
    characteristics = []
    for flag_name, flag_val in pefile.DLL_CHARACTERISTICS.items():
        if isinstance(flag_val, int) and (flags & flag_val): characteristics.append(flag_name)
    return characteristics if characteristics else ["NONE"]


def get_section_characteristics(flags: int) -> List[str]:
    characteristics = []
    for flag_name, flag_val in pefile.SECTION_CHARACTERISTICS.items():
        if isinstance(flag_val, int) and (flags & flag_val): characteristics.append(flag_name)
    return characteristics if characteristics else ["NONE"]


def get_relocation_type_str(reloc_type: int) -> str:
    reloc_types = {val: name for name, val in pefile.RELOCATION_TYPE.items()}
    return reloc_types.get(reloc_type, f"UNKNOWN_TYPE_{reloc_type}")


def get_symbol_type_str(sym_type: int) -> str:
    types = {
        0x0: "NULL", 0x1: "VOID", 0x2: "CHAR", 0x3: "SHORT",
        0x4: "INT", 0x5: "LONG", 0x6: "FLOAT", 0x7: "DOUBLE",
        0x8: "STRUCT", 0x9: "UNION", 0xA: "ENUM",
        0xB: "MOE (Member of Enum)", 0xC: "BYTE", 0xD: "WORD",
        0xE: "UINT", 0xF: "DWORD",
    }
    base_type = sym_type & 0x000F
    derived_type = (sym_type & 0x00F0) >> 4
    type_str = types.get(base_type, f"UNKNOWN_BASE({hex(base_type)})")
    if derived_type == pefile.IMAGE_SYM_DTYPE_POINTER:
        type_str = f"POINTER_TO_{type_str}"
    elif derived_type == pefile.IMAGE_SYM_DTYPE_FUNCTION:
        type_str = f"FUNCTION_RETURNING_{type_str}"
    elif derived_type == pefile.IMAGE_SYM_DTYPE_ARRAY:
        type_str = f"ARRAY_OF_{type_str}"
    if sym_type == 0x20:
        return "FUNCTION"
    return type_str


def get_symbol_storage_class_str(storage_class: int) -> str:
    classes = {
        0: "NULL", 1: "AUTOMATIC", 2: "EXTERNAL", 3: "STATIC",
        4: "REGISTER", 5: "EXTERNAL_DEF", 6: "LABEL",
        7: "UNDEFINED_LABEL", 8: "MEMBER_OF_STRUCT", 9: "ARGUMENT",
        10: "STRUCT_TAG", 11: "MEMBER_OF_UNION", 12: "UNION_TAG",
        13: "TYPE_DEFINITION", 14: "UNDEFINED_STATIC", 15: "ENUM_TAG",
        16: "MEMBER_OF_ENUM", 17: "REGISTER_PARAM", 18: "BIT_FIELD",
        100: "BLOCK", 101: "FUNCTION", 102: "END_OF_STRUCT",
        103: "FILE", 104: "SECTION", 105: "WEAK_EXTERNAL",
        107: "CLR_TOKEN",
    }
    if hasattr(pefile, 'SYMBOL_STORAGE_CLASSES'):
        pefile_classes = {v: k.replace("IMAGE_SYM_CLASS_", "") for k, v in pefile.SYMBOL_STORAGE_CLASSES.items()}
        classes.update(pefile_classes)
    return classes.get(storage_class, f"UNKNOWN_CLASS({storage_class})")


def _dump_aux_symbol_to_dict(parent_symbol_struct, aux_symbol_struct, aux_idx: int) -> Dict[str, Any]:
    aux_dict: Dict[str, Any] = {"aux_record_index": aux_idx + 1}
    parent_storage_class = parent_symbol_struct.StorageClass

    sym_class_file = getattr(pefile, 'IMAGE_SYM_CLASS_FILE', 103)
    sym_class_section = getattr(pefile, 'IMAGE_SYM_CLASS_SECTION', 104)
    sym_class_static = getattr(pefile, 'IMAGE_SYM_CLASS_STATIC', 3)
    sym_class_function = getattr(pefile, 'IMAGE_SYM_CLASS_FUNCTION', 101)
    sym_class_weak_external = getattr(pefile, 'IMAGE_SYM_CLASS_WEAK_EXTERNAL', 105)
    sym_dtype_function = getattr(pefile, 'IMAGE_SYM_DTYPE_FUNCTION', 2)

    if parent_storage_class == sym_class_file:
        name_bytes = getattr(aux_symbol_struct, 'Name', b'')
        if not name_bytes and hasattr(aux_symbol_struct, 'strings'):
            name_bytes = aux_symbol_struct.strings
        name_str = "N/A"
        if isinstance(name_bytes, bytes):
            try:
                name_str = name_bytes.decode('utf-8', 'ignore').rstrip('\x00')
            except Exception:
                name_str = name_bytes.hex()
        elif isinstance(name_bytes, str):
            name_str = name_bytes.rstrip('\x00')
        aux_dict["filename"] = name_str
        return aux_dict

    if (parent_storage_class == sym_class_section
            or (parent_storage_class == sym_class_static
                and parent_symbol_struct.SectionNumber > 0)):
        aux_dict["type"] = "Section Definition Aux Record"
        if hasattr(aux_symbol_struct, 'Length'):
            aux_dict["length"] = aux_symbol_struct.Length
        if hasattr(aux_symbol_struct, 'NumberOfRelocations'):
            aux_dict["number_of_relocations"] = aux_symbol_struct.NumberOfRelocations
        if hasattr(aux_symbol_struct, 'NumberOfLinenumbers'):
            aux_dict["number_of_linenumbers"] = aux_symbol_struct.NumberOfLinenumbers
        if hasattr(aux_symbol_struct, 'CheckSum'):
            aux_dict["checksum"] = hex(aux_symbol_struct.CheckSum)
        if hasattr(aux_symbol_struct, 'Number'):
            aux_dict["number_comdat"] = aux_symbol_struct.Number
        if hasattr(aux_symbol_struct, 'Selection'):
            sel_map = {
                0: "NODUPLICATES", 1: "ANY", 2: "SAME_SIZE",
                3: "EXACT_MATCH", 4: "ASSOCIATIVE", 5: "LARGEST",
            }
            sel_str = sel_map.get(
                aux_symbol_struct.Selection,
                f"UNKNOWN ({aux_symbol_struct.Selection})",
            )
            aux_dict["selection_comdat"] = sel_str
        return aux_dict

    is_func_rel = (
        (parent_symbol_struct.Type >> 4) == sym_dtype_function
        or parent_symbol_struct.Type == 0x20
    )
    if is_func_rel or parent_storage_class == sym_class_function:
        aux_dict["type"] = "Function-related Aux Record"
        if hasattr(aux_symbol_struct, 'TagIndex'):
            aux_dict["tag_index"] = aux_symbol_struct.TagIndex
        if hasattr(aux_symbol_struct, 'TotalSize'):
            aux_dict["total_size"] = aux_symbol_struct.TotalSize
        if hasattr(aux_symbol_struct, 'PointerToLinenumber'):
            aux_dict["pointer_to_linenumber"] = hex(aux_symbol_struct.PointerToLinenumber)
        if hasattr(aux_symbol_struct, 'PointerToNextFunction'):
            aux_dict["pointer_to_next_function"] = aux_symbol_struct.PointerToNextFunction
        if hasattr(aux_symbol_struct, 'Linenumber'):
            aux_dict["linenumber_lf"] = aux_symbol_struct.Linenumber
        return aux_dict

    if parent_storage_class == sym_class_weak_external:
        aux_dict["type"] = "Weak External Aux Record"
        if hasattr(aux_symbol_struct, 'TagIndex'):
            aux_dict["tag_index"] = aux_symbol_struct.TagIndex
        if hasattr(aux_symbol_struct, 'Characteristics'):
            char_val = aux_symbol_struct.Characteristics
            char_map = {
                1: "IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY",
                2: "IMAGE_WEAK_EXTERN_SEARCH_LIBRARY",
                3: "IMAGE_WEAK_EXTERN_SEARCH_ALIAS",
            }
            char_str = char_map.get(char_val, f"UNKNOWN ({hex(char_val)})")
            aux_dict["characteristics"] = char_str
        return aux_dict

    aux_dict["type"] = "Raw Auxiliary Data"
    raw_bytes = b''
    if isinstance(aux_symbol_struct, bytes):
        raw_bytes = aux_symbol_struct
    elif hasattr(aux_symbol_struct, '__pack__'):
        try:
            raw_bytes = aux_symbol_struct.__pack__()
        except Exception:
            pass
    if raw_bytes:
        suffix = "..." if len(raw_bytes) > 18 else ""
        aux_dict["hex_data"] = raw_bytes[:18].hex() + suffix
    else:
        raw_attrs = {}
        for attr_name in dir(aux_symbol_struct):
            if attr_name.startswith('_') or callable(getattr(aux_symbol_struct, attr_name)):
                continue
            attr_val = getattr(aux_symbol_struct, attr_name)
            if isinstance(attr_val, int):
                is_addr = any(kw in attr_name for kw in ('Pointer', 'Address', 'Offset'))
                raw_attrs[attr_name] = hex(attr_val) if is_addr else attr_val
            elif isinstance(attr_val, bytes):
                raw_attrs[attr_name] = attr_val.hex()
            else:
                raw_attrs[attr_name] = str(attr_val)
        aux_dict["attributes"] = raw_attrs
    return aux_dict
