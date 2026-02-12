"""PE file parsing functions - headers, sections, imports, exports, and more."""
import os
import io
import struct
import hashlib
import warnings
import re
import concurrent.futures
import logging

from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple, Callable

from pemcp.config import (
    logger, pefile, state,
    CRYPTOGRAPHY_AVAILABLE, SIGNIFY_AVAILABLE, YARA_AVAILABLE,
    PEID_USERDB_URL,
)
from pemcp.utils import (
    safe_print, format_timestamp,
    get_file_characteristics, get_dll_characteristics, get_section_characteristics,
    get_relocation_type_str, get_symbol_type_str, get_symbol_storage_class_str,
    _dump_aux_symbol_to_dict,
)
from pemcp.hashing import ssdeep_hasher
from pemcp.mock import MockPE
from pemcp.resources import ensure_peid_db_exists
from pemcp.parsers.signatures import parse_signature_file, find_pattern_in_data_regex, perform_yara_scan
from pemcp.parsers.capa import _parse_capa_analysis
from pemcp.parsers.floss import _parse_floss_analysis
from pemcp.parsers.strings import _extract_strings_from_data

if CRYPTOGRAPHY_AVAILABLE:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import pkcs7

if SIGNIFY_AVAILABLE:
    from signify.authenticode import AuthenticodeFile, AuthenticodeVerificationResult


# --- Safe parse helper for resilient analysis of malformed binaries ---
def _safe_parse(key: str, func: Callable, *args, **kwargs) -> Any:
    """Call *func* and return its result.  On any exception, return an error
    dict so that partial analysis results are still available."""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        logger.warning(f"Parser '{key}' failed: {type(e).__name__}: {e}")
        return {"error": f"{key} parsing failed: {type(e).__name__}: {e}"}


# --- Refactored PE Parsing Helper Functions ---
def _parse_file_hashes(data: bytes) -> Dict[str, Optional[str]]:
    hashes: Dict[str, Optional[str]] = {
        "md5": None, "sha1": None, "sha256": None, "ssdeep": None,
    }
    try:
        hashes["md5"] = hashlib.md5(data).hexdigest()
        hashes["sha1"] = hashlib.sha1(data).hexdigest()
        hashes["sha256"] = hashlib.sha256(data).hexdigest()
        try:
            hashes["ssdeep"] = ssdeep_hasher.hash(data)
        except Exception as e_ssdeep:
            logger.warning(f"ssdeep hash error: {e_ssdeep}")
            hashes["ssdeep"] = f"Error: {e_ssdeep}"
    except Exception as e_hash:
        logger.warning(f"File hash error: {e_hash}")
    return hashes


def _parse_dos_header(pe: pefile.PE) -> Dict[str, Any]:
    if hasattr(pe, 'DOS_HEADER') and pe.DOS_HEADER:
        return pe.DOS_HEADER.dump_dict()
    return {"error": "DOS Header not found or malformed."}


def _parse_nt_headers(pe: pefile.PE) -> Tuple[Dict[str, Any], str]:
    nt_headers_info: Dict[str, Any] = {}
    magic_type_str = "Unknown"

    if not (hasattr(pe, 'NT_HEADERS') and pe.NT_HEADERS):
        return {"error": "NT Headers not found."}, magic_type_str

    nt_headers_info['signature'] = hex(pe.NT_HEADERS.Signature)

    if hasattr(pe.NT_HEADERS, 'FILE_HEADER') and pe.NT_HEADERS.FILE_HEADER:
        fh_dict = pe.NT_HEADERS.FILE_HEADER.dump_dict()
        fh_dict['characteristics_list'] = get_file_characteristics(
            pe.NT_HEADERS.FILE_HEADER.Characteristics
        )
        fh_dict['TimeDateStamp_ISO'] = format_timestamp(
            pe.NT_HEADERS.FILE_HEADER.TimeDateStamp
        )
        nt_headers_info['file_header'] = fh_dict
    else:
        nt_headers_info['file_header'] = {"error": "File Header not found."}

    if hasattr(pe.NT_HEADERS, 'OPTIONAL_HEADER') and pe.NT_HEADERS.OPTIONAL_HEADER:
        oh_dict = pe.NT_HEADERS.OPTIONAL_HEADER.dump_dict()
        oh_dict['dll_characteristics_list'] = get_dll_characteristics(
            pe.NT_HEADERS.OPTIONAL_HEADER.DllCharacteristics
        )
        magic_val = pe.NT_HEADERS.OPTIONAL_HEADER.Magic
        if magic_val == 0x10b:
            magic_type_str = "PE32 (32-bit)"
        elif magic_val == 0x20b:
            magic_type_str = "PE32+ (64-bit)"
        oh_dict['pe_type'] = magic_type_str
        nt_headers_info['optional_header'] = oh_dict
    else:
        nt_headers_info['optional_header'] = {"error": "Optional Header not found."}

    return nt_headers_info, magic_type_str


def _parse_data_directories(pe: pefile.PE) -> List[Dict[str, Any]]:
    data_dirs_list = []
    if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
        for i, entry in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            entry_info = entry.dump_dict()
            entry_info['name'] = entry.name
            entry_info['index'] = i
            data_dirs_list.append(entry_info)
    return data_dirs_list


def _parse_sections(pe: pefile.PE) -> List[Dict[str, Any]]:
    sections_list = []
    if hasattr(pe, 'sections'):
        for section in pe.sections:
            sec_dict = section.dump_dict()
            sec_dict['name_str'] = section.Name.decode('utf-8', 'ignore').rstrip('\x00')
            sec_dict['characteristics_list'] = get_section_characteristics(section.Characteristics)
            sec_dict['entropy'] = section.get_entropy()
            try:
                section_data = section.get_data()
                sec_dict['md5'] = hashlib.md5(section_data).hexdigest()
                sec_dict['sha1'] = hashlib.sha1(section_data).hexdigest()
                sec_dict['sha256'] = hashlib.sha256(section_data).hexdigest()
                try:
                    sec_dict['ssdeep'] = ssdeep_hasher.hash(section_data)
                except Exception as e:
                    sec_dict['ssdeep'] = f"Error: {e}"
            except Exception as e:
                logger.warning(f"Section hash error {sec_dict['name_str']}: {e}")
            sections_list.append(sec_dict)
    return sections_list


def _parse_imports(pe: pefile.PE) -> List[Dict[str, Any]]:
    imports_list = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_info: Dict[str, Any] = {'dll_name': "Unknown"}
            try:
                dll_info['dll_name'] = entry.dll.decode('utf-8', 'ignore') if entry.dll else "N/A"
            except Exception:
                pass  # Keep 'Unknown' if decoding fails

            dll_info['struct'] = entry.struct.dump_dict()
            dll_info['symbols'] = []

            if hasattr(entry, 'imports'):
                for imp in entry.imports:
                    sym_info = {
                        'address': hex(imp.address) if imp.address is not None else None,
                        'name': imp.name.decode('utf-8', 'ignore') if imp.name else None,
                        'ordinal': imp.ordinal,
                        'bound': hex(imp.bound) if imp.bound is not None else None,
                        'hint_name_table_rva': (
                            hex(imp.hint_name_table_rva)
                            if hasattr(imp, 'hint_name_table_rva') and imp.hint_name_table_rva is not None
                            else None
                        ),
                        'import_by_ordinal': (
                            imp.import_by_ordinal
                            if hasattr(imp, 'import_by_ordinal')
                            else (imp.name is None)
                        ),
                    }
                    dll_info['symbols'].append(sym_info)
            imports_list.append(dll_info)
    return imports_list


def _parse_exports(pe: pefile.PE) -> Dict[str, Any]:
    exports_info: Dict[str, Any] = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        exports_info['struct'] = pe.DIRECTORY_ENTRY_EXPORT.struct.dump_dict()
        exports_info['name'] = (
            pe.DIRECTORY_ENTRY_EXPORT.name.decode('utf-8', 'ignore')
            if pe.DIRECTORY_ENTRY_EXPORT.name else None
        )
        exports_info['symbols'] = []
        if hasattr(pe.DIRECTORY_ENTRY_EXPORT, 'symbols'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                sym_info = {
                    'address': hex(exp.address) if exp.address is not None else None,
                    'name': exp.name.decode('utf-8', 'ignore') if exp.name else None,
                    'ordinal': exp.ordinal,
                    'forwarder': exp.forwarder.decode('utf-8', 'ignore') if exp.forwarder else None,
                }
                exports_info['symbols'].append(sym_info)
    return exports_info


def _parse_resources_summary(pe: pefile.PE) -> List[Dict[str, Any]]:
    resources_summary_list = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for res_type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_name_val = getattr(res_type_entry, 'id', None)
            type_name_str = pefile.RESOURCE_TYPE.get(type_name_val, str(type_name_val))

            if hasattr(res_type_entry, 'name') and res_type_entry.name is not None:
                try:
                    type_name_str = f"{res_type_entry.name.decode('utf-16le', 'ignore')} ({type_name_str})"
                except Exception:
                    type_name_str = f"{res_type_entry.name.decode('latin-1', 'ignore')} ({type_name_str})"

            if hasattr(res_type_entry, 'directory'):
                for res_id_entry in res_type_entry.directory.entries:
                    id_val = getattr(res_id_entry, 'id', None)
                    id_name_str = str(id_val)

                    if hasattr(res_id_entry, 'name') and res_id_entry.name is not None:
                        try:
                            id_name_str = (
                                f"{res_id_entry.name.decode('utf-16le', 'ignore')} "
                                f"(ID: {id_val if id_val is not None else 'N/A'})"
                            )
                        except Exception:
                            id_name_str = (
                                f"{res_id_entry.name.decode('latin-1', 'ignore')} "
                                f"(ID: {id_val if id_val is not None else 'N/A'})"
                            )
                    elif id_val is not None:
                        id_name_str = f"ID: {id_val}"
                    else:
                        id_name_str = "Unnamed/ID-less"

                    if hasattr(res_id_entry, 'directory'):
                        for res_lang_entry in res_id_entry.directory.entries:
                            if hasattr(res_lang_entry, 'data') and hasattr(res_lang_entry.data, 'struct'):
                                data_struct = res_lang_entry.data.struct
                                resources_summary_list.append({
                                    "type": type_name_str,
                                    "id_name": id_name_str,
                                    "lang_id": getattr(res_lang_entry, 'id', 'N/A'),
                                    "offset_to_data_rva": hex(getattr(data_struct, 'OffsetToData', 0)),
                                    "size": getattr(data_struct, 'Size', 0),
                                    "codepage": getattr(data_struct, 'CodePage', 0),
                                })
    return resources_summary_list


def _parse_version_info(pe: pefile.PE) -> Dict[str, Any]:
    ver_info: Dict[str, Any] = {}

    if hasattr(pe, 'VS_VERSIONINFO') and hasattr(pe.VS_VERSIONINFO, 'Value'):
        ver_info['vs_versioninfo_value'] = (
            pe.VS_VERSIONINFO.Value.decode('ascii', 'ignore')
            if pe.VS_VERSIONINFO.Value else None
        )

    if hasattr(pe, 'VS_FIXEDFILEINFO') and pe.VS_FIXEDFILEINFO:
        fixed_list = []
        for entry in pe.VS_FIXEDFILEINFO:
            fixed_dict = entry.dump_dict()
            fixed_dict['FileVersion_str'] = (
                f"{(entry.FileVersionMS >> 16)}.{(entry.FileVersionMS & 0xFFFF)}"
                f".{(entry.FileVersionLS >> 16)}.{(entry.FileVersionLS & 0xFFFF)}"
            )
            fixed_dict['ProductVersion_str'] = (
                f"{(entry.ProductVersionMS >> 16)}.{(entry.ProductVersionMS & 0xFFFF)}"
                f".{(entry.ProductVersionLS >> 16)}.{(entry.ProductVersionLS & 0xFFFF)}"
            )
            fixed_list.append(fixed_dict)
        ver_info['vs_fixedfileinfo'] = fixed_list

    if hasattr(pe, 'FileInfo') and pe.FileInfo:
        fi_blocks = []
        for fi_block in pe.FileInfo:
            block_detail: Dict[str, Any] = {}

            if hasattr(fi_block, 'entries'):
                # StringFileInfo
                block_detail['type'] = "StringFileInfo"
                st_tables = []
                for item in fi_block.entries:
                    st_entry: Dict[str, Any] = {
                        'lang_codepage': f"{item.Lang}/{item.CodePage}",
                        'entries': {},
                    }
                    if hasattr(item, 'entries') and isinstance(item.entries, dict):
                        for k, v in item.entries.items():
                            key_str = k.decode('utf-8', 'ignore') if isinstance(k, bytes) else str(k)
                            val_str = v.decode('utf-8', 'ignore') if isinstance(v, bytes) else str(v)
                            st_entry['entries'][key_str] = val_str
                    st_tables.append(st_entry)
                block_detail['string_tables'] = st_tables

            elif hasattr(fi_block, 'Var') and hasattr(fi_block.Var, 'entry'):
                # VarFileInfo
                block_detail['type'] = "VarFileInfo"
                var_entry = fi_block.Var.entry
                var_key = (
                    var_entry.szKey.decode('utf-8', 'ignore')
                    if isinstance(var_entry.szKey, bytes) else str(var_entry.szKey)
                )
                var_val = var_entry.Value
                var_val_str = var_val

                if isinstance(var_val, bytes) and len(var_val) == 4:
                    lang_id = struct.unpack('<H', var_val[:2])[0]
                    charset_id = struct.unpack('<H', var_val[2:])[0]
                    var_val_str = f"LangID={hex(lang_id)}, CharsetID={hex(charset_id)}"
                elif isinstance(var_val, bytes):
                    var_val_str = var_val.hex()

                block_detail['vars'] = {var_key: var_val_str}

            fi_blocks.append(block_detail)
        ver_info['file_info_blocks'] = fi_blocks

    return ver_info


def _parse_debug_info(pe: pefile.PE) -> List[Dict[str, Any]]:
    debug_list = []
    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        for entry in pe.DIRECTORY_ENTRY_DEBUG:
            dbg_item: Dict[str, Any] = {'struct': entry.struct.dump_dict()}
            dbg_item['type_str'] = pefile.DEBUG_TYPE.get(entry.struct.Type, "UNKNOWN")

            if entry.entry:
                dbg_item['entry_details'] = entry.entry.dump_dict()
                if (entry.struct.Type == pefile.DEBUG_TYPE['IMAGE_DEBUG_TYPE_CODEVIEW']
                        and hasattr(entry.entry, 'PdbFileName')):
                    try:
                        dbg_item['pdb_filename'] = (
                            entry.entry.PdbFileName.decode('utf-8', 'ignore').rstrip('\x00')
                        )
                    except Exception:
                        dbg_item['pdb_filename'] = (
                            entry.entry.PdbFileName.hex()
                            if isinstance(entry.entry.PdbFileName, bytes)
                            else str(entry.entry.PdbFileName)
                        )
            debug_list.append(dbg_item)
    return debug_list


def _parse_digital_signature(pe: pefile.PE, filepath: str, cryptography_available_flag: bool, signify_available_flag: bool) -> Dict[str, Any]:
    sig_info: Dict[str, Any] = {}
    sec_dir_idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
    if hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY') and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > sec_dir_idx:
        sec_dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_idx]
        sig_offset = sec_dir_entry.VirtualAddress
        sig_size = sec_dir_entry.Size
        sig_info['security_directory'] = {'offset': hex(sig_offset), 'size': hex(sig_size)}
        if sig_offset != 0 and sig_size != 0:
            sig_info['embedded_signature_present'] = True
            raw_sig_block = pe.get_data(sig_offset, sig_size)
            if cryptography_available_flag:
                crypto_certs = []
                try:
                    pkcs7_blob = None
                    if len(raw_sig_block) > 8:
                        cert_type = struct.unpack_from('<H', raw_sig_block, 6)[0]
                        if cert_type == 0x0002:
                            pkcs7_blob = raw_sig_block[8:]
                    if pkcs7_blob:
                        with warnings.catch_warnings():
                            warnings.simplefilter("ignore", UserWarning)
                            warnings.simplefilter("ignore", DeprecationWarning)
                            parsed = pkcs7.load_der_pkcs7_certificates(pkcs7_blob)
                        for idx, cert in enumerate(parsed):
                            crypto_certs.append({
                                "cert_index": idx + 1,
                                "subject": str(cert.subject.rfc4514_string()),
                                "issuer": str(cert.issuer.rfc4514_string()),
                                "serial_number": str(cert.serial_number),
                                "version": str(cert.version),
                                "not_valid_before_utc": str(cert.not_valid_before_utc),
                                "not_valid_after_utc": str(cert.not_valid_after_utc),
                            })
                        sig_info['cryptography_parsed_certs'] = crypto_certs
                except Exception as e:
                    sig_info['cryptography_parsed_certs_error'] = str(e)
            else:
                sig_info['cryptography_parsed_certs'] = "cryptography library not available"

            if signify_available_flag:
                signify_res = []
                try:
                    with io.BytesIO(pe.__data__) as f_mem:
                        auth_file = AuthenticodeFile.from_stream(f_mem)
                        status, err = auth_file.explain_verify()
                        item = {
                            "status_description": str(status),
                            "is_valid": status == AuthenticodeVerificationResult.OK,
                            "exception": str(err) if err else None,
                        }
                        signer_names = []
                        for sig in auth_file.signatures:
                            if hasattr(sig, 'signer_info'):
                                if hasattr(sig.signer_info, 'program_name') and sig.signer_info.program_name:
                                    signer_names.append(sig.signer_info.program_name)
                                elif hasattr(sig.signer_info, 'issuer'):
                                    signer_names.append(str(sig.signer_info.issuer))
                        if signer_names:
                            item["signers"] = signer_names
                        signify_res.append(item)
                except Exception as e:
                    signify_res.append({"error": f"Signify validation error: {e}"})
                sig_info['signify_validation'] = signify_res
            else:
                sig_info['signify_validation'] = {"status": "Signify library not available."}
        else:
            sig_info['embedded_signature_present'] = False
    return sig_info


def _perform_peid_scan(pe: pefile.PE, peid_db_path: Optional[str], verbose: bool, skip_full_peid_scan: bool, peid_scan_all_sigs_heuristically: bool) -> Dict[str, Any]:
    peid_results: Dict[str, Any] = {"ep_matches": [], "heuristic_matches": [], "status": "Not performed"}

    if not peid_db_path:
        logger.error("PEiD scan called without a database path (this indicates an issue with path defaulting).")
        peid_results["status"] = "PEiD DB path was not resolved prior to scan."
        return peid_results

    str_peid_db_path = str(peid_db_path)

    if not os.path.exists(str_peid_db_path):
        logger.info(f"PEiD DB '{str_peid_db_path}' not found. Attempting download...")
        if not ensure_peid_db_exists(PEID_USERDB_URL, str_peid_db_path, verbose):
            peid_results["status"] = f"PEiD DB '{str_peid_db_path}' not found and download failed."
            return peid_results

    custom_sigs = parse_signature_file(str_peid_db_path, verbose)
    if not custom_sigs:
        peid_results["status"] = f"No PEiD signatures loaded from '{str_peid_db_path}' (file might be empty or malformed)."
        return peid_results

    peid_results["status"] = "Scan performed."

    # Entry Point Scan
    if hasattr(pe, 'OPTIONAL_HEADER') and pe.OPTIONAL_HEADER.AddressOfEntryPoint:
        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        try:
            ep_sec = pe.get_section_by_rva(ep_rva)
            if ep_sec:
                ep_offset_sec = ep_rva - ep_sec.VirtualAddress
                ep_data = ep_sec.get_data(ep_offset_sec, 2048)  # Read 2KB from EP
                for sig in custom_sigs:
                    if sig['ep_only']:
                        match_name = find_pattern_in_data_regex(ep_data, sig, verbose, "Entry Point Area")
                        if match_name:
                            peid_results["ep_matches"].append(match_name)
        except Exception as e:
            logger.warning(f"PEiD EP scan error: {e}", exc_info=verbose)

    # Full File / Heuristic Scan
    if not skip_full_peid_scan:
        heuristic_matches_list: List[str] = []
        secs_to_scan = [
            s for s in pe.sections
            if hasattr(s, 'Characteristics')
            and bool(s.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])
        ]
        if not secs_to_scan and pe.sections:
            secs_to_scan = [pe.sections[0]]

        scan_tasks_args = []
        for sec in secs_to_scan:
            try:
                section_name_cleaned = sec.Name.decode('utf-8', 'ignore').rstrip('\x00')
                sec_data = sec.get_data()
                for sig in custom_sigs:
                    if peid_scan_all_sigs_heuristically or not sig['ep_only']:
                        scan_tasks_args.append((sec_data, sig, verbose, section_name_cleaned))
            except Exception as e:
                section_name_cleaned_for_log = "UnknownSection"
                try:
                    section_name_cleaned_for_log = sec.Name.decode('utf-8', 'ignore').rstrip('\x00')
                except Exception:
                    pass
                logger.warning(f"PEiD section data error {section_name_cleaned_for_log}: {e}")

        if scan_tasks_args:
            with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 1) as executor:
                futures = [executor.submit(find_pattern_in_data_regex, *args) for args in scan_tasks_args]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        res_name = future.result()
                        if res_name:
                            heuristic_matches_list.append(res_name)
                    except Exception as e:
                        logger.warning(f"PEiD scan thread error: {e}", exc_info=verbose)
        peid_results["heuristic_matches"] = list(set(heuristic_matches_list))

    peid_results["ep_matches"] = list(set(peid_results["ep_matches"]))
    return peid_results


def _parse_rich_header(pe: pefile.PE) -> Optional[Dict[str, Any]]:
    if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER:
        decoded = []
        raw_vals = list(pe.RICH_HEADER.values) if pe.RICH_HEADER.values else []
        for i in range(0, len(raw_vals), 2):
            if i + 1 < len(raw_vals):
                comp_id = raw_vals[i]
                count = raw_vals[i + 1]
                prod_id = comp_id >> 16
                build_num = comp_id & 0xFFFF
                decoded.append({
                    "product_id_hex": hex(prod_id),
                    "product_id_dec": prod_id,
                    "build_number": build_num,
                    "count": count,
                    "raw_comp_id": hex(comp_id),
                })
        return {
            'key_hex': pe.RICH_HEADER.key.hex() if isinstance(pe.RICH_HEADER.key, bytes) else str(pe.RICH_HEADER.key),
            'checksum': hex(pe.RICH_HEADER.checksum) if pe.RICH_HEADER.checksum is not None else None,
            'raw_values': raw_vals,
            'decoded_values': decoded,
            'raw_data_hex': pe.RICH_HEADER.raw_data.hex() if pe.RICH_HEADER.raw_data else None,
            'clear_data_hex': pe.RICH_HEADER.clear_data.hex() if pe.RICH_HEADER.clear_data else None,
        }
    return None


def _parse_delay_load_imports(pe: pefile.PE, magic_type_str: str) -> List[Dict[str, Any]]:
    IMG_ORDINAL_FLAG64 = 0x8000000000000000
    IMG_ORDINAL_FLAG32 = 0x80000000

    delay_imports_list = []
    if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            dll_name = "N/A"
            if entry.struct.szName:
                try:
                    dll_name = pe.get_string_at_rva(entry.struct.szName).decode('utf-8', 'ignore')
                except Exception:
                    pass

            delay_syms = []
            if entry.struct.pINT and hasattr(pe, 'OPTIONAL_HEADER'):
                thunk_rva = entry.struct.pINT
                ptr_size = 8 if magic_type_str == "PE32+ (64-bit)" else 4
                ord_flag = IMG_ORDINAL_FLAG64 if ptr_size == 8 else IMG_ORDINAL_FLAG32

                while True:
                    try:
                        thunk_val_raw = (
                            pe.get_qword_at_rva(thunk_rva) if ptr_size == 8
                            else pe.get_dword_at_rva(thunk_rva)
                        )
                        if thunk_val_raw == 0:
                            break

                        s_name, s_ord = None, None
                        if thunk_val_raw & ord_flag:
                            s_ord = thunk_val_raw & 0xFFFF
                        else:
                            name_rva = thunk_val_raw
                            try:
                                s_name = pe.get_string_at_rva(name_rva + 2).decode('utf-8', 'ignore')
                            except Exception as e_str:
                                logger.debug(f"Delay-load import string fetch error at RVA {hex(name_rva + 2)}: {e_str}")
                                s_name = "ErrorFetchingName"

                        delay_syms.append({
                            'name': s_name,
                            'ordinal': s_ord,
                            'thunk_rva': hex(thunk_rva),
                        })
                        thunk_rva += ptr_size
                    except pefile.PEFormatError as e_pe:
                        logger.debug(f"Delay-load import table parsing error (PEFormatError): {e_pe}")
                        break
                    except Exception as e_gen:
                        logger.warning(f"Unexpected error parsing delay-load import entry: {e_gen}")
                        break

            delay_imports_list.append({
                'dll_name': dll_name,
                'struct': entry.struct.dump_dict(),
                'symbols': delay_syms,
            })
    return delay_imports_list


def _parse_tls_info(pe: pefile.PE, magic_type_str: str) -> Optional[Dict[str, Any]]:
    if not (hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS
            and pe.DIRECTORY_ENTRY_TLS.struct):
        return None

    tls_struct = pe.DIRECTORY_ENTRY_TLS.struct
    tls_info: Dict[str, Any] = {'struct': tls_struct.dump_dict()}
    callbacks = []

    if tls_struct.AddressOfCallBacks and hasattr(pe, 'OPTIONAL_HEADER'):
        cb_va = tls_struct.AddressOfCallBacks
        ptr_size = 8 if magic_type_str == "PE32+ (64-bit)" else 4
        max_cb = 20
        count = 0

        while cb_va != 0 and count < max_cb:
            try:
                func_va_ptr_offset = pe.get_offset_from_virtual_address(cb_va)
                raw_data = pe.get_data(func_va_ptr_offset, ptr_size)
                func_va = (
                    pe.get_qword_from_data(raw_data, 0) if ptr_size == 8
                    else pe.get_dword_from_data(raw_data, 0)
                )
                if func_va == 0:
                    break
                callbacks.append({
                    'va': hex(func_va),
                    'rva': hex(func_va - pe.OPTIONAL_HEADER.ImageBase),
                })
                cb_va += ptr_size
                count += 1
            except AttributeError as e_pefile_va:
                logger.debug(
                    f"TLS callback VA {hex(cb_va)}->RVA/offset conversion error: "
                    f"{e_pefile_va} (likely VA out of mapped range)"
                )
                break
            except Exception as e:
                logger.debug(f"TLS callback parse error VA {hex(cb_va)}: {e}")
                break

    tls_info['callbacks'] = callbacks
    return tls_info


def _parse_load_config(pe: pefile.PE) -> Optional[Dict[str, Any]]:
    if not (hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG')
            and pe.DIRECTORY_ENTRY_LOAD_CONFIG
            and pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct):
        return None

    lc = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
    load_config_dict: Dict[str, Any] = {'struct': lc.dump_dict()}

    if hasattr(lc, 'GuardFlags'):
        gf_list = []
        gf_map = {
            0x100: "CF_INSTRUMENTED",
            0x200: "CFW_INSTRUMENTED",
            0x400: "CF_FUNCTION_TABLE_PRESENT",
            0x800: "SECURITY_COOKIE_UNUSED",
            0x1000: "PROTECT_DELAYLOAD_IAT",
            0x2000: "DELAYLOAD_IAT_IN_ITS_OWN_SECTION",
            0x4000: "CF_EXPORT_SUPPRESSION_INFO_PRESENT",
            0x8000: "CF_ENABLE_EXPORT_SUPPRESSION",
            0x10000: "CF_LONGJUMP_TABLE_PRESENT",
            0x100000: "RETPOLINE_PRESENT",
            0x1000000: "EH_CONTINUATION_TABLE_PRESENT",
            0x2000000: "XFG_ENABLED",
            0x4000000: "MEMTAG_PRESENT",
            0x8000000: "CET_SHADOW_STACK_PRESENT",
        }
        for flag_val, flag_name in gf_map.items():
            if lc.GuardFlags & flag_val:
                gf_list.append(f"IMAGE_GUARD_{flag_name}")
        load_config_dict['guard_flags_list'] = gf_list

    return load_config_dict


def _parse_com_descriptor(pe: pefile.PE) -> Optional[Dict[str, Any]]:
    com_desc_idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']

    if not (hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY')
            and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > com_desc_idx
            and pe.OPTIONAL_HEADER.DATA_DIRECTORY[com_desc_idx].VirtualAddress != 0
            and hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR')
            and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR
            and hasattr(pe.DIRECTORY_ENTRY_COM_DESCRIPTOR, 'struct')):
        return None

    com_desc = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.struct
    com_dict: Dict[str, Any] = {'struct': com_desc.dump_dict()}
    flags_list = []

    flags_map = {
        0x1: "ILONLY",
        0x2: "32BITREQUIRED",
        0x4: "IL_LIBRARY",
        0x8: "STRONGNAMESIGNED",
        0x10: "NATIVE_ENTRYPOINT",
        0x10000: "TRACKDEBUGDATA",
        0x20000: "32BITPREFERRED",
    }
    if hasattr(com_desc, 'Flags'):
        for val, name in flags_map.items():
            if com_desc.Flags & val:
                flags_list.append(f"COMIMAGE_FLAGS_{name}")

    com_dict['flags_list'] = flags_list
    return com_dict


def _parse_overlay_data(pe: pefile.PE) -> Optional[Dict[str, Any]]:
    offset = pe.get_overlay_data_start_offset()
    if offset is not None:
        data = pe.get_overlay()
        return {
            'offset': hex(offset),
            'size': len(data) if data else 0,
            'md5': hashlib.md5(data).hexdigest() if data else None,
            'sha256': hashlib.sha256(data).hexdigest() if data else None,
            'sample_hex': data[:64].hex() if data else None,
        }
    return None


def _parse_base_relocations(pe: pefile.PE) -> List[Dict[str, Any]]:
    relocs_list = []
    if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
        for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
            block: Dict[str, Any] = {'struct': base_reloc.struct.dump_dict(), 'entries': []}
            if hasattr(base_reloc, 'entries'):
                for entry in base_reloc.entries:
                    block['entries'].append({
                        'rva': hex(entry.rva),
                        'type': entry.type,
                        'type_str': get_relocation_type_str(entry.type),
                        'is_padding': getattr(entry, 'is_padding', False),
                    })
            relocs_list.append(block)
    return relocs_list


def _parse_bound_imports(pe: pefile.PE) -> List[Dict[str, Any]]:
    bound_list = []
    if hasattr(pe, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
        for desc in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
            d_dict: Dict[str, Any] = {
                'struct': desc.struct.dump_dict(),
                'name': None,
                'forwarder_refs': [],
            }
            try:
                d_dict['name'] = desc.name.decode('utf-8', 'ignore') if desc.name else "N/A"
            except Exception:
                pass

            if hasattr(desc, 'entries'):
                for ref in desc.entries:
                    r_dict: Dict[str, Any] = {'struct': ref.struct.dump_dict(), 'name': None}
                    try:
                        r_dict['name'] = ref.name.decode('utf-8', 'ignore') if ref.name else "N/A"
                    except Exception:
                        pass
                    d_dict['forwarder_refs'].append(r_dict)
            bound_list.append(d_dict)
    return bound_list


def _parse_exception_data(pe: pefile.PE) -> List[Dict[str, Any]]:
    ex_list = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXCEPTION') and pe.DIRECTORY_ENTRY_EXCEPTION:
        for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
            if hasattr(entry, 'struct'):
                entry_dump = entry.struct.dump_dict()
                machine = pe.FILE_HEADER.Machine
                if machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                    entry_dump['note'] = "x64 RUNTIME_FUNCTION ( unwind info at UnwindInfoAddressRVA )"
                elif (machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']
                        and hasattr(entry.struct, 'ExceptionHandler')):
                    entry_dump['note'] = "x86 SEH Frame (uncommon, usually handled by OS)"
                elif machine in [
                    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARMNT'],
                    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM64'],
                ]:
                    entry_dump['note'] = "ARM/ARM64 RUNTIME_FUNCTION"
                ex_list.append(entry_dump)
    return ex_list


def _parse_coff_symbols(pe: pefile.PE) -> List[Dict[str, Any]]:
    coff_list = []
    if not (hasattr(pe, 'FILE_HEADER')
            and pe.FILE_HEADER.PointerToSymbolTable != 0
            and pe.FILE_HEADER.NumberOfSymbols > 0
            and hasattr(pe, 'SYMBOLS')):
        return coff_list

    idx = 0
    while idx < len(pe.SYMBOLS):
        symbol = pe.SYMBOLS[idx]
        sym_dict = {
            'name_str': (
                symbol.name.decode('utf-8', 'ignore').rstrip('\x00')
                if isinstance(symbol.name, bytes) else str(symbol.name)
            ),
            'value': symbol.Value,
            'section_number': symbol.SectionNumber,
            'type': symbol.Type,
            'storage_class': symbol.StorageClass,
            'number_of_aux_symbols': symbol.NumberOfAuxSymbols,
            'type_str': get_symbol_type_str(symbol.Type),
            'storage_class_str': get_symbol_storage_class_str(symbol.StorageClass),
            'raw_struct': symbol.struct.dump_dict(),
            'auxiliary_symbols': [],
        }
        idx += 1
        if symbol.NumberOfAuxSymbols > 0:
            for aux_i in range(symbol.NumberOfAuxSymbols):
                if idx < len(pe.SYMBOLS):
                    aux_obj = None
                    if hasattr(pe.SYMBOLS[idx], 'struct'):
                        aux_obj = pe.SYMBOLS[idx].struct
                    if aux_obj:
                        sym_dict['auxiliary_symbols'].append(
                            _dump_aux_symbol_to_dict(symbol.struct, aux_obj, aux_i)
                        )
                    idx += 1
                else:
                    break
        coff_list.append(sym_dict)
    return coff_list


def _verify_checksum(pe: pefile.PE) -> Dict[str, Any]:
    if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'CheckSum'):
        hdr_sum = pe.OPTIONAL_HEADER.CheckSum
        calc_sum = pe.generate_checksum()
        return {
            'header_checksum': hex(hdr_sum),
            'calculated_checksum': hex(calc_sum),
            'matches': (
                hdr_sum == calc_sum if hdr_sum != 0
                else "Header checksum is 0 (not verified)"
            ),
        }
    return {"error": "Checksum info not available."}


# --- Main PE Parsing Logic ---
def _parse_pe_to_dict(pe: pefile.PE, filepath: str,
                      peid_db_path: Optional[str],
                      yara_rules_path: Optional[str],
                      capa_rules_path: Optional[str],
                      capa_sigs_path: Optional[str],
                      verbose: bool,
                      skip_full_peid_scan: bool,
                      peid_scan_all_sigs_heuristically: bool,
                      floss_min_len_arg: int,
                      floss_verbose_level_arg: int,
                      floss_script_debug_level_arg: int,
                      floss_format_hint_arg: str,
                      floss_disabled_types_arg: List[str],
                      floss_only_types_arg: List[str],
                      floss_functions_to_analyze_arg: List[int],
                      floss_quiet_mode_arg: bool,
                      analyses_to_skip: Optional[List[str]] = None,
                      progress_callback: Optional[Callable[[int, int, str], None]] = None
                      ) -> Dict[str, Any]:

    def _report(step: int, total: int, message: str) -> None:
        if progress_callback:
            try:
                progress_callback(step, total, message)
            except Exception:
                pass  # Never let progress reporting break the analysis

    try:
        state.pefile_version = pefile.__version__
    except AttributeError:
        state.pefile_version = "Unknown"

    if analyses_to_skip is None:
        analyses_to_skip = []
    analyses_to_skip = [analysis.lower() for analysis in analyses_to_skip]

    _report(0, 100, "Starting PE analysis...")

    pe_info_dict: Dict[str, Any] = {"filepath": filepath, "pefile_version": state.pefile_version}

    # --- DETECT RAW MODE ---
    is_raw_mode = isinstance(pe, MockPE)
    if is_raw_mode:
        pe_info_dict["mode"] = "shellcode_raw"
        pe_info_dict["note"] = "Standard PE headers/imports/exports skipped in raw mode."
    else:
        pe_info_dict["mode"] = "pe_executable"

    # Basic hashes (Works for both)
    _report(5, 100, "Computing file hashes...")
    pe_info_dict['file_hashes'] = _parse_file_hashes(pe.__data__)

    if not is_raw_mode:
        # Run PE-specific parsers only if it's a real PE.
        # Each parser is individually guarded so that a failure in one
        # (e.g. due to a corrupted structure) does not prevent other
        # parsers from producing results.
        _report(10, 100, "Parsing PE headers and structures...")

        # NT headers are special: they return magic_type_str needed by later parsers
        magic_type_str = "Unknown"
        try:
            nt_headers_info, magic_type_str = _parse_nt_headers(pe)
            pe_info_dict['nt_headers'] = nt_headers_info
        except Exception as e:
            logger.warning(f"Parser 'nt_headers' failed: {type(e).__name__}: {e}")
            pe_info_dict['nt_headers'] = {"error": f"nt_headers parsing failed: {type(e).__name__}: {e}"}

        pe_info_dict['dos_header'] = _safe_parse('dos_header', _parse_dos_header, pe)
        pe_info_dict['data_directories'] = _safe_parse('data_directories', _parse_data_directories, pe)
        pe_info_dict['sections'] = _safe_parse('sections', _parse_sections, pe)
        pe_info_dict['imports'] = _safe_parse('imports', _parse_imports, pe)
        pe_info_dict['exports'] = _safe_parse('exports', _parse_exports, pe)
        pe_info_dict['resources_summary'] = _safe_parse('resources_summary', _parse_resources_summary, pe)
        pe_info_dict['version_info'] = _safe_parse('version_info', _parse_version_info, pe)
        pe_info_dict['debug_info'] = _safe_parse('debug_info', _parse_debug_info, pe)
        pe_info_dict['digital_signature'] = _safe_parse(
            'digital_signature', _parse_digital_signature, pe, filepath,
            CRYPTOGRAPHY_AVAILABLE, SIGNIFY_AVAILABLE,
        )
        pe_info_dict['rich_header'] = _safe_parse('rich_header', _parse_rich_header, pe)
        pe_info_dict['delay_load_imports'] = _safe_parse('delay_load_imports', _parse_delay_load_imports, pe, magic_type_str)
        pe_info_dict['tls_info'] = _safe_parse('tls_info', _parse_tls_info, pe, magic_type_str)
        pe_info_dict['load_config'] = _safe_parse('load_config', _parse_load_config, pe)
        pe_info_dict['com_descriptor'] = _safe_parse('com_descriptor', _parse_com_descriptor, pe)
        pe_info_dict['overlay_data'] = _safe_parse('overlay_data', _parse_overlay_data, pe)
        pe_info_dict['base_relocations'] = _safe_parse('base_relocations', _parse_base_relocations, pe)
        pe_info_dict['bound_imports'] = _safe_parse('bound_imports', _parse_bound_imports, pe)
        pe_info_dict['exception_data'] = _safe_parse('exception_data', _parse_exception_data, pe)
        pe_info_dict['coff_symbols'] = _safe_parse('coff_symbols', _parse_coff_symbols, pe)
        pe_info_dict['checksum_verification'] = _safe_parse('checksum_verification', _verify_checksum, pe)
    else:
        # Set minimal defaults for raw mode to avoid UI errors in subsequent tools
        pe_info_dict['digital_signature'] = {"status": "Not applicable for raw shellcode"}

    _report(40, 100, "Running signature scans...")
    if "peid" not in analyses_to_skip:
        if is_raw_mode:
             pe_info_dict['peid_matches'] = {"status": "Skipped (Raw Shellcode Mode)"}
        else:
             pe_info_dict['peid_matches'] = _safe_parse(
                 'peid_matches', _perform_peid_scan, pe, peid_db_path,
                 verbose, skip_full_peid_scan, peid_scan_all_sigs_heuristically,
             )
    else:
        pe_info_dict['peid_matches'] = {"status": "Skipped by user request", "ep_matches": [], "heuristic_matches": []}
        logger.info("PEiD analysis skipped by request.")

    _report(50, 100, "Running YARA scan...")
    if "yara" not in analyses_to_skip:
        pe_info_dict['yara_matches'] = _safe_parse(
            'yara_matches', perform_yara_scan, filepath, pe.__data__,
            yara_rules_path, YARA_AVAILABLE, verbose,
        )
    else:
        pe_info_dict['yara_matches'] = [{"status": "Skipped by user request"}]
        logger.info("YARA analysis skipped by request.")

    _report(60, 100, "Running capa analysis...")
    if "capa" not in analyses_to_skip:
        pe_info_dict['capa_analysis'] = _safe_parse(
            'capa_analysis', _parse_capa_analysis, pe, filepath,
            capa_rules_path, capa_sigs_path, verbose,
        )
    else:
        pe_info_dict['capa_analysis'] = {"status": "Skipped by user request", "results": None, "error": None}
        logger.info("Capa analysis skipped by request.")

    _report(75, 100, "Running FLOSS string analysis...")
    if "floss" not in analyses_to_skip:
        pe_info_dict['floss_analysis'] = _safe_parse(
            'floss_analysis', _parse_floss_analysis,
            filepath,
            floss_min_len_arg,
            floss_verbose_level_arg,
            floss_script_debug_level_arg,
            floss_format_hint_arg,
            floss_disabled_types_arg,
            floss_only_types_arg,
            floss_functions_to_analyze_arg,
            floss_quiet_mode_arg,
        )
    else:
        pe_info_dict['floss_analysis'] = {"status": "Skipped by user request", "strings": {}}
        logger.info("FLOSS analysis skipped by request.")

    _report(90, 100, "Extracting basic strings...")
    pe_info_dict['basic_ascii_strings'] = [
        {"offset": hex(offset), "string": s, "source_type": "basic_ascii"}
        for offset, s in _extract_strings_from_data(pe.__data__, 5)
    ]


    pe_info_dict['pefile_warnings'] = pe.get_warnings()
    _report(100, 100, "Analysis complete.")
    return pe_info_dict
