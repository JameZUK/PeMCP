"""MCP tools powered by Binary Refinery for file extraction and document analysis.

Provides archive extraction, installer unpacking, Office document analysis,
PDF operations, and embedded file detection through a single dispatched tool.
"""
import asyncio
import hashlib

from typing import Dict, Any, Optional

from pemcp.config import state, logger, Context
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size
from pemcp.mcp._refinery_helpers import (
    _require_refinery, _bytes_to_hex, _safe_decode,
    _get_file_data, _get_data_from_hex_or_file,
    _MAX_INPUT_SIZE_LARGE as _MAX_INPUT_SIZE,
)


@tool_decorator
async def refinery_extract(
    ctx: Context,
    operation: str,
    data_hex: Optional[str] = None,
    sub_operation: Optional[str] = None,
    password: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """Extract files and content from containers via Binary Refinery.

    Operations:
    - 'archive': Extract from archives. sub_operation: auto/zip/7z/tar/gz/cab/iso/cpio/chm/ace.
    - 'installer': Unpack installers. sub_operation (required): nsis/innosetup/pyinstaller/nuitka/node/asar/minidump.
    - 'office': Extract from Office docs. sub_operation: streams/vba/vba_pcode/vba_strings/text/metadata/excel_cells/rtf_objects/onenote.
    - 'office_decrypt': Decrypt password-protected Office documents (requires password param).
    - 'xlm_deobfuscate': Deobfuscate Excel 4.0 (XLM) macros.
    - 'pdf': Extract objects and streams from PDFs (optional password param).
    - 'embedded': Auto-detect and extract all embedded files (PE, ZIP, ELF, PDF, etc.).

    Args:
        ctx: MCP Context.
        operation: (str) One of the operations listed above.
        data_hex: (Optional[str]) Data as hex. If None, uses loaded file.
        sub_operation: (Optional[str]) Sub-operation for archive/installer/office.
        password: (Optional[str]) Password for encrypted archives, Office docs, or PDFs.
        limit: (int) Max items to extract. Default 100.

    Returns:
        Dictionary with extracted file metadata.
    """
    _require_refinery("refinery_extract")

    op = operation.lower()

    _SUPPORTED = [
        "archive", "installer", "office", "office_decrypt",
        "xlm_deobfuscate", "pdf", "embedded",
    ]
    if op not in _SUPPORTED:
        return {"error": f"Unknown operation '{operation}'.", "supported": sorted(_SUPPORTED)}

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        if op == "embedded":
            data = data[:_MAX_INPUT_SIZE]
            await ctx.warning(f"Data truncated to {_MAX_INPUT_SIZE} bytes.")
        else:
            raise RuntimeError(f"Input too large ({len(data)} bytes). Max: {_MAX_INPUT_SIZE}.")

    await ctx.info(f"Extract operation: {op}" + (f" ({sub_operation})" if sub_operation else ""))

    # ── archive: ZIP, 7z, TAR, CAB, ISO, etc. ──────────────────────
    if op == "archive":
        _ARCHIVE_MAP = {
            "auto": "refinery.units.formats.archive.xt:xt",
            "zip":  "refinery.units.formats.archive.xtzip:xtzip",
            "7z":   "refinery.units.formats.archive.xt7z:xt7z",
            "tar":  "refinery.units.formats.archive.xttar:xttar",
            "gz":   "refinery.units.formats.archive.xtgz:xtgz",
            "cab":  "refinery.units.formats.archive.xtcab:xtcab",
            "iso":  "refinery.units.formats.archive.xtiso:xtiso",
            "cpio": "refinery.units.formats.archive.xtcpio:xtcpio",
            "chm":  "refinery.units.formats.archive.xtchm:xtchm",
            "ace":  "refinery.units.formats.archive.xtace:xtace",
        }
        atype = (sub_operation or "auto").lower()
        if atype not in _ARCHIVE_MAP:
            return {"error": f"Unknown archive type '{sub_operation}'.", "supported": sorted(_ARCHIVE_MAP.keys())}
        mod_path, cls_name = _ARCHIVE_MAP[atype].rsplit(":", 1)

        def _run_archive():
            import importlib
            mod = importlib.import_module(mod_path)
            unit_cls = getattr(mod, cls_name)
            kwargs = {}
            if password:
                kwargs["pwd"] = password.encode("utf-8")
            results = []
            for chunk in data | unit_cls(**kwargs):
                raw = bytes(chunk)
                entry: Dict[str, Any] = {
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "md5": hashlib.md5(raw).hexdigest(),
                }
                if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                    if "path" in chunk.meta:
                        entry["path"] = str(chunk.meta["path"])
                    if "name" in chunk.meta:
                        entry["name"] = str(chunk.meta["name"])
                entry["preview_hex"] = raw[:64].hex()
                results.append(entry)
                if len(results) >= limit:
                    break
            return results

        results = await asyncio.to_thread(_run_archive)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "archive_type": atype,
            "files_extracted": len(results),
            "input_size": len(data),
            "results": results,
        }, "refinery_extract")

    # ── installer: NSIS, InnoSetup, PyInstaller, etc. ───────────────
    if op == "installer":
        _INSTALLER_MAP = {
            "nsis":        "refinery.units.formats.archive.xtnsis:xtnsis",
            "innosetup":   "refinery.units.formats.archive.xtinno:xtinno",
            "pyinstaller": "refinery.units.formats.archive.xtpyi:xtpyi",
            "nuitka":      "refinery.units.formats.archive.xtnuitka:xtnuitka",
            "node":        "refinery.units.formats.archive.xtnode:xtnode",
            "asar":        "refinery.units.formats.archive.xtasar:xtasar",
            "minidump":    "refinery.units.formats.archive.xtdmp:xtdmp",
        }
        if not sub_operation:
            return {"error": "installer requires sub_operation.", "supported": sorted(_INSTALLER_MAP.keys())}
        itype = sub_operation.lower()
        if itype not in _INSTALLER_MAP:
            return {"error": f"Unknown installer type '{sub_operation}'.", "supported": sorted(_INSTALLER_MAP.keys())}
        mod_path, cls_name = _INSTALLER_MAP[itype].rsplit(":", 1)

        def _run_installer():
            import importlib
            mod = importlib.import_module(mod_path)
            unit_cls = getattr(mod, cls_name)
            results = []
            for chunk in data | unit_cls():
                raw = bytes(chunk)
                entry: Dict[str, Any] = {
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
                if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                    for key in ("path", "name", "type"):
                        if key in chunk.meta:
                            entry[key] = str(chunk.meta[key])
                entry["preview_hex"] = raw[:64].hex()
                results.append(entry)
                if len(results) >= limit:
                    break
            return results

        results = await asyncio.to_thread(_run_installer)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "installer_type": itype,
            "files_extracted": len(results),
            "input_size": len(data),
            "results": results,
        }, "refinery_extract")

    # ── office: OLE streams, VBA, metadata, etc. ────────────────────
    if op == "office":
        _OFFICE_MAP = {
            "streams":     "refinery.units.formats.office.xtdoc:xtdoc",
            "vba":         "refinery.units.formats.office.xtvba:xtvba",
            "vba_pcode":   "refinery.units.formats.office.vbapc:vbapc",
            "vba_strings": "refinery.units.formats.office.vbastr:vbastr",
            "text":        "refinery.units.formats.office.doctxt:doctxt",
            "metadata":    "refinery.units.formats.office.docmeta:docmeta",
            "excel_cells": "refinery.units.formats.office.xlxtr:xlxtr",
            "rtf_objects": "refinery.units.formats.office.xtrtf:xtrtf",
            "onenote":     "refinery.units.formats.office.xtone:xtone",
        }
        sop = (sub_operation or "streams").lower()
        if sop not in _OFFICE_MAP:
            return {"error": f"Unknown office sub_operation '{sub_operation}'.", "supported": sorted(_OFFICE_MAP.keys())}
        mod_path, cls_name = _OFFICE_MAP[sop].rsplit(":", 1)

        def _run_office():
            import importlib
            mod = importlib.import_module(mod_path)
            unit_cls = getattr(mod, cls_name)
            results = []
            for chunk in data | unit_cls():
                raw = bytes(chunk)
                entry: Dict[str, Any] = {
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
                if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                    for key in ("path", "name", "type", "stream"):
                        if key in chunk.meta:
                            entry[key] = str(chunk.meta[key])
                if sop in ("vba", "vba_pcode", "vba_strings", "text", "metadata"):
                    entry["text"] = _safe_decode(raw)[:4000]
                else:
                    entry["preview_hex"] = raw[:128].hex()
                results.append(entry)
                if len(results) >= limit:
                    break
            return results

        results = await asyncio.to_thread(_run_office)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "sub_operation": sop,
            "items_found": len(results),
            "input_size": len(data),
            "results": results,
        }, "refinery_extract")

    # ── office_decrypt: decrypt password-protected Office docs ──────
    if op == "office_decrypt":
        if not password:
            return {"error": "office_decrypt requires the 'password' parameter."}

        def _run_office_decrypt():
            from refinery.units.formats.office.officecrypt import officecrypt
            return data | officecrypt(password.encode("utf-8")) | bytes

        result = await asyncio.to_thread(_run_office_decrypt)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "input_size": len(data),
            "output_size": len(result),
            "sha256": hashlib.sha256(result).hexdigest(),
            "preview_hex": result[:128].hex(),
            "status": "decrypted" if result != data else "unchanged",
        }, "refinery_extract")

    # ── xlm_deobfuscate: Excel 4.0 XLM macros ──────────────────────
    if op == "xlm_deobfuscate":
        def _run_xlm():
            from refinery.units.formats.office.xlmdeobf import xlmdeobf
            try:
                return data | xlmdeobf() | bytes
            except Exception as e:
                if "XLMMacroDeobfuscator" in str(e) or "Missing" in type(e).__name__:
                    raise RuntimeError(
                        "xlmdeobf requires the 'XLMMacroDeobfuscator' package. "
                        "Install it with: pip install XLMMacroDeobfuscator"
                    ) from e
                raise

        result = await asyncio.to_thread(_run_xlm)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "input_size": len(data),
            "output_size": len(result),
            "deobfuscated_text": _safe_decode(result)[:8000],
        }, "refinery_extract")

    # ── pdf: extract objects and streams ─────────────────────────────
    if op == "pdf":
        def _run_pdf():
            working_data = data
            if password:
                from refinery.units.formats.pdfcrypt import pdfcrypt
                working_data = working_data | pdfcrypt(password.encode("utf-8")) | bytes
            from refinery.units.formats.pdf import xtpdf
            results = []
            for chunk in working_data | xtpdf():
                raw = bytes(chunk)
                entry: Dict[str, Any] = {
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
                if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                    for key in ("path", "name", "type", "obj"):
                        if key in chunk.meta:
                            entry[key] = str(chunk.meta[key])
                text = _safe_decode(raw)[:1000]
                if text.isprintable() or any(c in text for c in "\n\r\t"):
                    entry["text_preview"] = text
                else:
                    entry["preview_hex"] = raw[:128].hex()
                results.append(entry)
                if len(results) >= limit:
                    break
            return results

        results = await asyncio.to_thread(_run_pdf)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "items_extracted": len(results),
            "input_size": len(data),
            "encrypted": password is not None,
            "results": results,
        }, "refinery_extract")

    # ── embedded: auto-detect all embedded files ────────────────────
    # op == "embedded"
    def _run_embedded():
        from refinery.units.pattern.subfiles import subfiles
        results = []
        for chunk in data | subfiles():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "md5": hashlib.md5(raw).hexdigest(),
            }
            if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                for key in ("path", "name", "mime", "ext", "offset"):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            if raw[:2] == b"MZ":
                entry["detected_type"] = "PE executable"
            elif raw[:4] == b"PK\x03\x04":
                entry["detected_type"] = "ZIP archive"
            elif raw[:4] == b"\x7fELF":
                entry["detected_type"] = "ELF binary"
            elif raw[:5] == b"%PDF-":
                entry["detected_type"] = "PDF document"
            elif raw[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                entry["detected_type"] = "OLE document"
            entry["preview_hex"] = raw[:64].hex()
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run_embedded)
    return await _check_mcp_response_size(ctx, {
        "operation": op,
        "files_found": len(results),
        "input_size": len(data),
        "results": results,
    }, "refinery_extract")
