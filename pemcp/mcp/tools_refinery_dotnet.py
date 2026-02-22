"""MCP tools powered by Binary Refinery for .NET binary analysis.

Provides deep .NET/CLR analysis: metadata headers, managed resources,
string extraction, CIL/MSIL disassembly, constant fields, blob extraction,
deserialization, and single-file app unpacking.
"""
import asyncio
import hashlib

from typing import Dict, Any, Optional, List

from pemcp.config import state, logger, Context
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from pemcp.mcp._refinery_helpers import (
    _require_refinery, _safe_decode, _bytes_to_hex, _hex_to_bytes,
    _get_file_data, _MAX_INPUT_SIZE_LARGE as _MAX_INPUT_SIZE,
    _MAX_OUTPUT_ITEMS,
)


# ===================================================================
#  1. .NET METADATA HEADERS
# ===================================================================

@tool_decorator
async def refinery_dotnet_headers(
    ctx: Context,
) -> Dict[str, Any]:
    """
    Extract .NET CLR metadata headers from the loaded PE file using Binary Refinery.

    Parses the CLR header, metadata tables, assembly info, type definitions,
    method definitions, and other .NET-specific structures. Works with both
    .NET Framework and .NET Core assemblies.

    See also: dotnet_analyze() for pefile/dnfile-based .NET analysis.

    Args:
        ctx: The MCP Context object.

    Returns:
        Dictionary with .NET header information as structured JSON.
    """
    _require_refinery("refinery_dotnet_headers")
    _check_pe_loaded("refinery_dotnet_headers")

    data = _get_file_data()
    await ctx.info(f"Extracting .NET headers from {state.filepath}...")

    def _run():
        from refinery.units.formats.pe.dotnet.dnhdr import dnhdr
        return data | dnhdr() | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "filepath": state.filepath,
        "output_size": len(result),
        "headers_json": _safe_decode(result)[:8000],
    }, "refinery_dotnet_headers")


# ===================================================================
#  2. .NET MANAGED RESOURCES
# ===================================================================

@tool_decorator
async def refinery_dotnet_resources(
    ctx: Context,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Extract .NET managed resources from the loaded PE file using Binary Refinery.

    Extracts resources embedded in the .NET assembly's manifest, including
    embedded files, images, serialized objects, and string tables. Malware
    often hides payloads in .NET resources.

    Args:
        ctx: The MCP Context object.
        limit: (int) Max resources to extract. Default 100.

    Returns:
        Dictionary with extracted resources (metadata + preview).
    """
    _require_refinery("refinery_dotnet_resources")
    _check_pe_loaded("refinery_dotnet_resources")

    data = _get_file_data()
    await ctx.info(f"Extracting .NET managed resources...")

    def _run():
        from refinery.units.formats.pe.dotnet.dnrc import dnrc
        results = []
        for chunk in data | dnrc():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('path', 'name', 'type'):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            # Check if resource looks like an embedded PE
            if raw[:2] == b'MZ':
                entry["detected_type"] = "Embedded PE"
            elif raw[:4] == b'PK\x03\x04':
                entry["detected_type"] = "Embedded ZIP"
            entry["preview_hex"] = raw[:64].hex()
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "filepath": state.filepath,
        "resources_found": len(results),
        "results": results,
    }, "refinery_dotnet_resources")


# ===================================================================
#  3. .NET MANAGED RESOURCE SUB-FILES
# ===================================================================

@tool_decorator
async def refinery_dotnet_managed_resources(
    ctx: Context,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Extract sub-files from .NET managed resource containers using Binary Refinery.

    Goes deeper than dnrc by parsing ResourceManager containers and extracting
    individual embedded items from .resources files. Useful when payloads are
    packed inside nested resource containers.

    Args:
        ctx: The MCP Context object.
        limit: (int) Max items to extract. Default 100.

    Returns:
        Dictionary with extracted managed resource items.
    """
    _require_refinery("refinery_dotnet_managed_resources")
    _check_pe_loaded("refinery_dotnet_managed_resources")

    data = _get_file_data()
    await ctx.info("Extracting .NET managed resource sub-files...")

    def _run():
        from refinery.units.formats.pe.dotnet.dnmr import dnmr
        results = []
        for chunk in data | dnmr():
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
        "filepath": state.filepath,
        "items_found": len(results),
        "results": results,
    }, "refinery_dotnet_managed_resources")


# ===================================================================
#  4. .NET STRINGS
# ===================================================================

@tool_decorator
async def refinery_dotnet_strings(
    ctx: Context,
    limit: int = 500,
) -> Dict[str, Any]:
    """
    Extract strings from .NET metadata streams using Binary Refinery.

    Extracts strings from the #Strings and #US (User Strings) metadata
    streams in a .NET assembly. These often contain API names, class names,
    configuration data, and hardcoded secrets.

    Args:
        ctx: The MCP Context object.
        limit: (int) Max strings to extract. Default 500.

    Returns:
        Dictionary with extracted .NET strings.
    """
    _require_refinery("refinery_dotnet_strings")
    _check_pe_loaded("refinery_dotnet_strings")

    data = _get_file_data()
    await ctx.info("Extracting .NET metadata strings...")

    def _run():
        from refinery.units.formats.pe.dotnet.dnstr import dnstr
        results = []
        for chunk in data | dnstr():
            raw = bytes(chunk)
            text = _safe_decode(raw)
            if text.strip():
                entry: Dict[str, Any] = {"string": text[:500]}
                if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                    for key in ('stream', 'index', 'token'):
                        if key in chunk.meta:
                            entry[key] = str(chunk.meta[key])
                results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "filepath": state.filepath,
        "strings_found": len(results),
        "results": results,
    }, "refinery_dotnet_strings")


# ===================================================================
#  5. .NET BLOBS
# ===================================================================

@tool_decorator
async def refinery_dotnet_blobs(
    ctx: Context,
    limit: int = 200,
) -> Dict[str, Any]:
    """
    Extract blobs from the .NET #Blob metadata stream using Binary Refinery.

    The #Blob stream contains binary data like method signatures, custom
    attributes, field initializers, and marshaling descriptors. Malware
    may store encrypted payloads or configuration in blob entries.

    Args:
        ctx: The MCP Context object.
        limit: (int) Max blobs to extract. Default 200.

    Returns:
        Dictionary with extracted blob entries.
    """
    _require_refinery("refinery_dotnet_blobs")
    _check_pe_loaded("refinery_dotnet_blobs")

    data = _get_file_data()
    await ctx.info("Extracting .NET blob stream entries...")

    def _run():
        from refinery.units.formats.pe.dotnet.dnblob import dnblob
        results = []
        for chunk in data | dnblob():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
                "hex": _bytes_to_hex(raw, 256),
            }
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('index', 'token'):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            # Try text decode
            text = _safe_decode(raw)
            if len(raw) < 256 and all(c.isprintable() or c in '\n\r\t' for c in text):
                entry["text"] = text
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "filepath": state.filepath,
        "blobs_found": len(results),
        "results": results,
    }, "refinery_dotnet_blobs")


# ===================================================================
#  6. .NET CIL/MSIL DISASSEMBLY
# ===================================================================

@tool_decorator
async def refinery_dotnet_disassemble(
    ctx: Context,
) -> Dict[str, Any]:
    """
    Disassemble .NET CIL/MSIL bytecode using Binary Refinery.

    Produces a human-readable disassembly of the Common Intermediate Language
    (CIL) instructions in a .NET assembly. Useful for understanding .NET
    malware behavior without a full decompiler.

    See also: dotnet_disassemble_method() for pefile/dnfile-based per-method disassembly.

    Args:
        ctx: The MCP Context object.

    Returns:
        Dictionary with CIL disassembly text.
    """
    _require_refinery("refinery_dotnet_disassemble")
    _check_pe_loaded("refinery_dotnet_disassemble")

    data = _get_file_data()
    await ctx.info("Disassembling .NET CIL bytecode...")

    def _run():
        from refinery.units.formats.pe.dotnet.dnopc import dnopc
        results = []
        for chunk in data | dnopc():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
                "disassembly": _safe_decode(raw)[:4000],
            }
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('name', 'token', 'method', 'type'):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            results.append(entry)
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "filepath": state.filepath,
        "methods_disassembled": len(results),
        "results": results,
    }, "refinery_dotnet_disassemble")


# ===================================================================
#  7. .NET CONSTANT FIELDS
# ===================================================================

@tool_decorator
async def refinery_dotnet_fields(
    ctx: Context,
    limit: int = 500,
) -> Dict[str, Any]:
    """
    Extract constant field values from .NET assemblies using Binary Refinery.

    Extracts the initial values of constant (static readonly / const) fields
    defined in .NET types. Malware frequently stores keys, C2 URLs, and
    configuration values as class constants.

    Args:
        ctx: The MCP Context object.
        limit: (int) Max fields to extract. Default 500.

    Returns:
        Dictionary with extracted constant field values.
    """
    _require_refinery("refinery_dotnet_fields")
    _check_pe_loaded("refinery_dotnet_fields")

    data = _get_file_data()
    await ctx.info("Extracting .NET constant fields...")

    def _run():
        from refinery.units.formats.pe.dotnet.dnfields import dnfields
        results = []
        for chunk in data | dnfields():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {"size": len(raw)}
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('name', 'type', 'class', 'token'):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            text = _safe_decode(raw)
            if len(raw) < 512 and all(c.isprintable() or c in '\n\r\t\x00' for c in text):
                entry["value_text"] = text.rstrip('\x00')
            else:
                entry["value_hex"] = _bytes_to_hex(raw, 256)
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "filepath": state.filepath,
        "fields_found": len(results),
        "results": results,
    }, "refinery_dotnet_fields")


# ===================================================================
#  8. .NET ARRAY INITIALIZERS
# ===================================================================

@tool_decorator
async def refinery_dotnet_arrays(
    ctx: Context,
    limit: int = 200,
) -> Dict[str, Any]:
    """
    Extract .NET array initializer data using Binary Refinery.

    Finds and extracts byte arrays that are initialized in .NET code via
    RuntimeHelpers.InitializeArray. These often contain encrypted payloads,
    shellcode, or embedded resources in .NET malware.

    Args:
        ctx: The MCP Context object.
        limit: (int) Max arrays to extract. Default 200.

    Returns:
        Dictionary with extracted array data.
    """
    _require_refinery("refinery_dotnet_arrays")
    _check_pe_loaded("refinery_dotnet_arrays")

    data = _get_file_data()
    await ctx.info("Extracting .NET array initializers...")

    def _run():
        from refinery.units.formats.pe.dotnet.dnarrays import dnarrays
        results = []
        for chunk in data | dnarrays():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "hex": _bytes_to_hex(raw, 512),
            }
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('name', 'token', 'type'):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            # Check for embedded PE
            if raw[:2] == b'MZ':
                entry["detected_type"] = "Embedded PE"
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "filepath": state.filepath,
        "arrays_found": len(results),
        "results": results,
    }, "refinery_dotnet_arrays")


# ===================================================================
#  9. .NET SINGLE-FILE APP EXTRACTION
# ===================================================================

@tool_decorator
async def refinery_dotnet_sfx(
    ctx: Context,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Extract files from .NET single-file applications using Binary Refinery.

    .NET 5+ supports publishing as a single-file executable that bundles all
    assemblies. This tool extracts the individual assemblies and resources
    from such bundles.

    Args:
        ctx: The MCP Context object.
        limit: (int) Max files to extract. Default 100.

    Returns:
        Dictionary with extracted assemblies and resources.
    """
    _require_refinery("refinery_dotnet_sfx")
    _check_pe_loaded("refinery_dotnet_sfx")

    data = _get_file_data()
    await ctx.info("Extracting .NET single-file application bundle...")

    def _run():
        from refinery.units.formats.pe.dotnet.dnsfx import dnsfx
        results = []
        for chunk in data | dnsfx():
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
        "filepath": state.filepath,
        "files_extracted": len(results),
        "results": results,
    }, "refinery_dotnet_sfx")


# ===================================================================
#  10. .NET DESERIALIZATION
# ===================================================================

@tool_decorator
async def refinery_dotnet_deserialize(
    ctx: Context,
    data_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Deserialize .NET BinaryFormatter data to JSON using Binary Refinery.

    Converts serialized .NET objects (BinaryFormatter/SoapFormatter) into
    readable JSON. Used for analyzing deserialization exploits and
    understanding serialized object graphs.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Serialized data as hex. If None, uses loaded file.

    Returns:
        Dictionary with deserialized object structure.
    """
    _require_refinery("refinery_dotnet_deserialize")

    if data_hex:
        data = _hex_to_bytes(data_hex)
    else:
        data = _get_file_data()

    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes). Max {_MAX_INPUT_SIZE}.")

    await ctx.info(f"Deserializing .NET object ({len(data)} bytes)...")

    def _run():
        from refinery.units.formats.pe.dotnet.dnds import dnds
        return data | dnds() | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "input_size": len(data),
        "output_size": len(result),
        "deserialized_json": _safe_decode(result)[:8000],
    }, "refinery_dotnet_deserialize")
