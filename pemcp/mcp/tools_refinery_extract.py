"""MCP tools powered by Binary Refinery for file extraction and document analysis.

Covers archive extraction (ZIP, 7z, TAR, CAB, ISO, etc.), installer unpacking
(NSIS, InnoSetup, PyInstaller, etc.), Office document analysis (VBA macros,
XLM deobfuscation, encrypted docs), and PDF operations.
"""
import asyncio
import hashlib

from typing import Dict, Any, Optional, List

from pemcp.config import state, logger, Context
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size
from pemcp.mcp._refinery_helpers import (
    _require_refinery, _bytes_to_hex, _safe_decode,
    _get_file_data, _get_data_from_hex_or_file,
    _MAX_INPUT_SIZE_LARGE as _MAX_INPUT_SIZE,
)

_MAX_OUTPUT_ITEMS = 200


# ===================================================================
#  1. ARCHIVE EXTRACTION
# ===================================================================

@tool_decorator
async def refinery_extract_archive(
    ctx: Context,
    archive_type: str = "auto",
    data_hex: Optional[str] = None,
    limit: int = 100,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Extract files from archives using Binary Refinery.

    Supports: zip, 7z, tar, gz, cab, iso, cpio, chm, ace, auto (auto-detect).
    Can extract from the loaded file or from provided hex data.

    Args:
        ctx: The MCP Context object.
        archive_type: (str) Archive format: 'auto', 'zip', '7z', 'tar', 'gz',
            'cab', 'iso', 'cpio', 'chm', 'ace'. Default 'auto'.
        data_hex: (Optional[str]) Archive data as hex. If None, uses loaded file.
        limit: (int) Max files to extract. Default 100.
        password: (Optional[str]) Password for encrypted archives.

    Returns:
        Dictionary with extracted file metadata (paths, sizes, hashes).
    """
    _require_refinery("refinery_extract_archive")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes). Max: {_MAX_INPUT_SIZE}.")

    _ARCHIVE_MAP = {
        "auto": "refinery.units.formats.archive.xt:xt",
        "zip": "refinery.units.formats.archive.xtzip:xtzip",
        "7z": "refinery.units.formats.archive.xt7z:xt7z",
        "tar": "refinery.units.formats.archive.xttar:xttar",
        "gz": "refinery.units.formats.archive.xtgz:xtgz",
        "cab": "refinery.units.formats.archive.xtcab:xtcab",
        "iso": "refinery.units.formats.archive.xtiso:xtiso",
        "cpio": "refinery.units.formats.archive.xtcpio:xtcpio",
        "chm": "refinery.units.formats.archive.xtchm:xtchm",
        "ace": "refinery.units.formats.archive.xtace:xtace",
    }

    atype = archive_type.lower()
    if atype not in _ARCHIVE_MAP:
        return {"error": f"Unknown archive type '{archive_type}'.", "supported": sorted(_ARCHIVE_MAP.keys())}

    await ctx.info(f"Extracting files from {atype.upper()} archive ({len(data)} bytes)...")
    mod_path, cls_name = _ARCHIVE_MAP[atype].rsplit(":", 1)

    def _run():
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
            # Extract metadata if available
            if hasattr(chunk, 'meta'):
                meta = chunk.meta
                if isinstance(meta, dict):
                    if 'path' in meta:
                        entry["path"] = str(meta['path'])
                    if 'name' in meta:
                        entry["name"] = str(meta['name'])
            entry["preview_hex"] = raw[:64].hex()
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "archive_type": atype,
        "files_extracted": len(results),
        "input_size": len(data),
        "results": results,
    }, "refinery_extract_archive")


# ===================================================================
#  2. INSTALLER UNPACKING
# ===================================================================

@tool_decorator
async def refinery_extract_installer(
    ctx: Context,
    installer_type: str,
    data_hex: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Extract files from software installers and packed executables using Binary Refinery.

    Supports: nsis, innosetup, pyinstaller, nuitka, node, asar, minidump.

    Args:
        ctx: The MCP Context object.
        installer_type: (str) Installer format: 'nsis', 'innosetup', 'pyinstaller',
            'nuitka', 'node', 'asar', 'minidump'.
        data_hex: (Optional[str]) Installer data as hex. If None, uses loaded file.
        limit: (int) Max files to extract. Default 100.

    Returns:
        Dictionary with extracted file metadata.
    """
    _require_refinery("refinery_extract_installer")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes). Max: {_MAX_INPUT_SIZE}.")

    _INSTALLER_MAP = {
        "nsis": "refinery.units.formats.archive.xtnsis:xtnsis",
        "innosetup": "refinery.units.formats.archive.xtinno:xtinno",
        "pyinstaller": "refinery.units.formats.archive.xtpyi:xtpyi",
        "nuitka": "refinery.units.formats.archive.xtnuitka:xtnuitka",
        "node": "refinery.units.formats.archive.xtnode:xtnode",
        "asar": "refinery.units.formats.archive.xtasar:xtasar",
        "minidump": "refinery.units.formats.archive.xtdmp:xtdmp",
    }

    itype = installer_type.lower()
    if itype not in _INSTALLER_MAP:
        return {"error": f"Unknown installer type '{installer_type}'.", "supported": sorted(_INSTALLER_MAP.keys())}

    await ctx.info(f"Extracting from {itype} installer ({len(data)} bytes)...")
    mod_path, cls_name = _INSTALLER_MAP[itype].rsplit(":", 1)

    def _run():
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
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('path', 'name', 'type'):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            entry["preview_hex"] = raw[:64].hex()
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "installer_type": itype,
        "files_extracted": len(results),
        "input_size": len(data),
        "results": results,
    }, "refinery_extract_installer")


# ===================================================================
#  3. OFFICE DOCUMENT ANALYSIS
# ===================================================================

@tool_decorator
async def refinery_extract_office(
    ctx: Context,
    operation: str = "streams",
    data_hex: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Extract content from Microsoft Office documents using Binary Refinery.

    Operations:
    - 'streams': Extract all OLE streams from .doc/.xls/.ppt files.
    - 'vba': Extract VBA macro source code.
    - 'vba_pcode': Disassemble VBA p-code (bytecode).
    - 'vba_strings': Extract strings from VBA modules.
    - 'text': Extract plain text content from documents.
    - 'metadata': Extract document metadata (author, dates, etc.).
    - 'excel_cells': Extract Excel cell values.
    - 'rtf_objects': Extract embedded objects from RTF files.
    - 'onenote': Extract from OneNote files.

    Args:
        ctx: The MCP Context object.
        operation: (str) Operation to perform. Default 'streams'.
        data_hex: (Optional[str]) Document data as hex. If None, uses loaded file.
        limit: (int) Max items to return. Default 100.

    Returns:
        Dictionary with extracted content.
    """
    _require_refinery("refinery_extract_office")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    _OP_MAP = {
        "streams": "refinery.units.formats.office.xtdoc:xtdoc",
        "vba": "refinery.units.formats.office.xtvba:xtvba",
        "vba_pcode": "refinery.units.formats.office.vbapc:vbapc",
        "vba_strings": "refinery.units.formats.office.vbastr:vbastr",
        "text": "refinery.units.formats.office.doctxt:doctxt",
        "metadata": "refinery.units.formats.office.docmeta:docmeta",
        "excel_cells": "refinery.units.formats.office.xlxtr:xlxtr",
        "rtf_objects": "refinery.units.formats.office.xtrtf:xtrtf",
        "onenote": "refinery.units.formats.office.xtone:xtone",
    }

    op = operation.lower()
    if op not in _OP_MAP:
        return {"error": f"Unknown operation '{operation}'.", "supported": sorted(_OP_MAP.keys())}

    await ctx.info(f"Office document operation: {op}")
    mod_path, cls_name = _OP_MAP[op].rsplit(":", 1)

    def _run():
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
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('path', 'name', 'type', 'stream'):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            # Text-oriented operations get full text output
            if op in ("vba", "vba_pcode", "vba_strings", "text", "metadata"):
                entry["text"] = _safe_decode(raw)[:4000]
            else:
                entry["preview_hex"] = raw[:128].hex()
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "operation": op,
        "items_found": len(results),
        "input_size": len(data),
        "results": results,
    }, "refinery_extract_office")


@tool_decorator
async def refinery_office_decrypt(
    ctx: Context,
    password: str,
    data_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Decrypt password-protected Microsoft Office documents using Binary Refinery.

    Supports Office 97-2003 (.doc, .xls, .ppt) and OOXML (.docx, .xlsx, .pptx)
    formats with RC4, AES-128, and AES-256 encryption.

    Args:
        ctx: The MCP Context object.
        password: (str) Document password.
        data_hex: (Optional[str]) Encrypted document as hex. If None, uses loaded file.

    Returns:
        Dictionary with decrypted document (hex + metadata).
    """
    _require_refinery("refinery_office_decrypt")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    await ctx.info(f"Decrypting Office document with password...")

    def _run():
        from refinery.units.formats.office.officecrypt import officecrypt
        return data | officecrypt(password.encode("utf-8")) | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "input_size": len(data),
        "output_size": len(result),
        "sha256": hashlib.sha256(result).hexdigest(),
        "preview_hex": result[:128].hex(),
        "status": "decrypted" if result != data else "unchanged",
    }, "refinery_office_decrypt")


@tool_decorator
async def refinery_deobfuscate_xlm(
    ctx: Context,
    data_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Deobfuscate Excel 4.0 (XLM) macros using Binary Refinery.

    XLM macros are a common malware delivery mechanism in malicious Excel files.
    This tool simplifies obfuscated XLM macro formulas to reveal true intent.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Excel file as hex. If None, uses loaded file.

    Returns:
        Dictionary with deobfuscated XLM macro content.
    """
    _require_refinery("refinery_deobfuscate_xlm")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    await ctx.info("Deobfuscating Excel 4.0 XLM macros...")

    def _run():
        from refinery.units.formats.office.xlmdeobf import xlmdeobf
        unit = xlmdeobf()
        # xlmdeobf depends on the 'xlrd2' package.  If it is missing,
        # binary-refinery replaces the unit class with a MissingModule
        # stub that is not callable.  Detect this and raise a clear error.
        if not callable(getattr(unit, 'process', None)):
            raise RuntimeError(
                "xlmdeobf requires the 'xlrd2' package which is not installed. "
                "Install it with: pip install xlrd2"
            )
        return data | unit | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "input_size": len(data),
        "output_size": len(result),
        "deobfuscated_text": _safe_decode(result)[:8000],
    }, "refinery_deobfuscate_xlm")


# ===================================================================
#  4. PDF OPERATIONS
# ===================================================================

@tool_decorator
async def refinery_extract_pdf(
    ctx: Context,
    data_hex: Optional[str] = None,
    password: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Extract objects and streams from PDF files, optionally decrypting them.

    Extracts embedded objects, streams, JavaScript, and other content
    from PDF files. Handles both encrypted and unencrypted PDFs.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) PDF data as hex. If None, uses loaded file.
        password: (Optional[str]) PDF password for encrypted documents.
        limit: (int) Max items to extract. Default 100.

    Returns:
        Dictionary with extracted PDF objects.
    """
    _require_refinery("refinery_extract_pdf")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    await ctx.info(f"Extracting from PDF ({len(data)} bytes)...")

    def _run():
        results = []

        # If password provided, decrypt first
        working_data = data
        if password:
            from refinery.units.formats.pdfcrypt import pdfcrypt
            working_data = working_data | pdfcrypt(password.encode("utf-8")) | bytes

        from refinery.units.formats.pdf.pdf import pdf
        for chunk in working_data | pdf():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('path', 'name', 'type', 'obj'):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            # Try text decode for streams
            text = _safe_decode(raw)[:1000]
            if text.isprintable() or any(c in text for c in '\n\r\t'):
                entry["text_preview"] = text
            else:
                entry["preview_hex"] = raw[:128].hex()
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "items_extracted": len(results),
        "input_size": len(data),
        "encrypted": password is not None,
        "results": results,
    }, "refinery_extract_pdf")


# ===================================================================
#  5. EMBEDDED FILE AUTO-DETECTION
# ===================================================================

@tool_decorator
async def refinery_extract_embedded(
    ctx: Context,
    data_hex: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    Automatically detect and extract all embedded files from data using Binary Refinery.

    Uses the 'subfiles' unit which applies heuristics and magic byte detection
    to find and extract any embedded files within a binary blob — PE executables,
    archives, documents, images, certificates, and more.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Data as hex. If None, uses loaded file.
        limit: (int) Max files to extract. Default 50.

    Returns:
        Dictionary with all detected embedded files.
    """
    _require_refinery("refinery_extract_embedded")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        data = data[:_MAX_INPUT_SIZE]
        await ctx.warning(f"Data truncated to {_MAX_INPUT_SIZE} bytes.")

    await ctx.info(f"Auto-detecting embedded files in {len(data)} bytes...")

    def _run():
        from refinery.units.pattern.subfiles import subfiles
        results = []
        for chunk in data | subfiles():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "md5": hashlib.md5(raw).hexdigest(),
            }
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('path', 'name', 'mime', 'ext', 'offset'):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            # Identify by magic bytes
            if raw[:2] == b'MZ':
                entry["detected_type"] = "PE executable"
            elif raw[:4] == b'PK\x03\x04':
                entry["detected_type"] = "ZIP archive"
            elif raw[:4] == b'\x7fELF':
                entry["detected_type"] = "ELF binary"
            elif raw[:5] == b'%PDF-':
                entry["detected_type"] = "PDF document"
            elif raw[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
                entry["detected_type"] = "OLE document"
            entry["preview_hex"] = raw[:64].hex()
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "files_found": len(results),
        "input_size": len(data),
        "results": results,
    }, "refinery_extract_embedded")
