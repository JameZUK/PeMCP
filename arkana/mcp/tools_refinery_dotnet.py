"""MCP tools powered by Binary Refinery for .NET binary analysis.

Provides deep .NET/CLR analysis through a single dispatched tool:
metadata headers, managed resources, string extraction, CIL/MSIL
disassembly, constant fields, blob extraction, deserialization,
and single-file app unpacking.
"""
import asyncio
import hashlib
import os

from typing import Dict, Any, List, Optional

from arkana.config import state, logger, Context
from arkana.constants import MAX_TOOL_LIMIT
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.mcp._refinery_helpers import (
    _require_refinery, _safe_decode, _bytes_to_hex, _hex_to_bytes,
    _get_file_data, _write_output_and_register_artifact,
    _MAX_INPUT_SIZE_LARGE as _MAX_INPUT_SIZE,
    _MAX_OUTPUT_ITEMS,
)


# ── Internal dispatch helpers ────────────────────────────────────────

def _iter_chunks_with_meta(data, unit_cls, meta_keys, limit):
    """Run a refinery unit and collect chunk metadata up to *limit*."""
    count = 0
    for chunk in data | unit_cls():
        raw = bytes(chunk)
        entry: Dict[str, Any] = {"size": len(raw)}
        if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
            for key in meta_keys:
                if key in chunk.meta:
                    entry[key] = str(chunk.meta[key])
        yield raw, entry
        count += 1
        if count >= limit:
            break


def _build_resource_entry(raw, entry, *, include_hash=True, preview_bytes=64):
    """Add common fields (hash, detected type, preview) to *entry*."""
    if include_hash:
        entry["sha256"] = hashlib.sha256(raw).hexdigest()
    if raw[:2] == b"MZ":
        entry["detected_type"] = "Embedded PE"
    elif raw[:4] == b"PK\x03\x04":
        entry["detected_type"] = "Embedded ZIP"
    entry["preview_hex"] = raw[:preview_bytes].hex()


# ── Dispatched .NET tool ─────────────────────────────────────────────

@tool_decorator
async def refinery_dotnet(
    ctx: Context,
    operation: str,
    data_hex: Optional[str] = None,
    limit: int = 20,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Analyse .NET assemblies via Binary Refinery.

    Operations:
    - 'headers': Extract CLR metadata headers (tables, assembly info, type/method defs).
    - 'resources': Extract .NET managed resources (embedded files, images, serialized objects).
    - 'managed_resources': Extract sub-files from ResourceManager containers.
    - 'strings': Extract strings from #Strings/#US metadata streams.
    - 'blobs': Extract blobs from #Blob metadata stream.
    - 'disassemble': Disassemble CIL/MSIL bytecode per method.
    - 'fields': Extract constant field values (keys, C2 URLs, config).
    - 'arrays': Extract byte-array initializer data (shellcode, encrypted payloads).
    - 'sfx': Extract files from .NET single-file application bundles.
    - 'deserialize': Deserialize BinaryFormatter data to JSON.

    Args:
        ctx: MCP Context.
        operation: (str) One of the operations listed above.
        data_hex: (Optional[str]) Data as hex. If None, uses the loaded file.
        limit: (int) Max items to return (where applicable). Default 20.
        output_path: (Optional[str]) Directory to save extracted files (resources/arrays/sfx).
            Each file is saved with its name or file_N.bin and registered as an artifact.

    Returns:
        Dictionary with operation-specific results.
    """
    _require_refinery("refinery_dotnet")
    limit = max(1, min(limit, MAX_TOOL_LIMIT))

    op = operation.lower()

    _OP_MAP = {
        "headers":            "refinery.units.formats.pe.dotnet.dnhdr:dnhdr",
        "resources":          "refinery.units.formats.pe.dotnet.dnrc:dnrc",
        "managed_resources":  "refinery.units.formats.pe.dotnet.dnmr:dnmr",
        "strings":            "refinery.units.formats.pe.dotnet.dnstr:dnstr",
        "blobs":              "refinery.units.formats.pe.dotnet.dnblob:dnblob",
        "disassemble":        "refinery.units.formats.pe.dotnet.dnopc:dnopc",
        "fields":             "refinery.units.formats.pe.dotnet.dnfields:dnfields",
        "arrays":             "refinery.units.formats.pe.dotnet.dnarrays:dnarrays",
        "sfx":                "refinery.units.formats.pe.dotnet.dnsfx:dnsfx",
        "deserialize":        "refinery.units.formats.pe.dotnet.dnds:dnds",
    }

    if op not in _OP_MAP:
        return {"error": f"Unknown operation '{operation}'.", "supported": sorted(_OP_MAP.keys())}

    # deserialize can work on hex data; everything else needs a loaded PE
    if op == "deserialize":
        if data_hex:
            data = _hex_to_bytes(data_hex)
        else:
            data = _get_file_data()
        if len(data) > _MAX_INPUT_SIZE:
            raise RuntimeError(f"Input too large ({len(data)} bytes). Max {_MAX_INPUT_SIZE}.")
    else:
        _check_pe_loaded("refinery_dotnet")
        data = _get_file_data()

    await ctx.info(f".NET operation: {op}")
    mod_path, cls_name = _OP_MAP[op].rsplit(":", 1)

    # ── headers / deserialize: single-output units ──────────────────
    if op in ("headers", "deserialize"):
        def _run_single():
            import importlib
            mod = importlib.import_module(mod_path)
            unit_cls = getattr(mod, cls_name)
            return data | unit_cls() | bytes

        result = await asyncio.to_thread(_run_single)
        resp: Dict[str, Any] = {"operation": op, "output_size": len(result)}
        if op == "headers":
            resp["filepath"] = state.filepath
            resp["headers_json"] = _safe_decode(result, max_len=8000)
        else:
            resp["input_size"] = len(data)
            resp["deserialized_json"] = _safe_decode(result, max_len=8000)
        return await _check_mcp_response_size(ctx, resp, "refinery_dotnet")

    # ── disassemble: multi-output, text-oriented ────────────────────
    if op == "disassemble":
        def _run_disasm():
            import importlib
            mod = importlib.import_module(mod_path)
            unit_cls = getattr(mod, cls_name)
            results = []
            for chunk in data | unit_cls():
                raw = bytes(chunk)
                entry: Dict[str, Any] = {
                    "size": len(raw),
                    "disassembly": _safe_decode(raw, max_len=4000),
                }
                if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                    for key in ("name", "token", "method", "type"):
                        if key in chunk.meta:
                            entry[key] = str(chunk.meta[key])
                results.append(entry)
                if len(results) >= limit:
                    break
            return results

        results = await asyncio.to_thread(_run_disasm)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "filepath": state.filepath,
            "methods_disassembled": len(results),
            "results": results,
        }, "refinery_dotnet")

    # ── strings: text items ─────────────────────────────────────────
    if op == "strings":
        def _run_strings():
            import importlib
            mod = importlib.import_module(mod_path)
            unit_cls = getattr(mod, cls_name)
            results = []
            for chunk in data | unit_cls():
                raw = bytes(chunk)
                text = _safe_decode(raw)
                if text.strip():
                    entry: Dict[str, Any] = {"string": text[:500]}
                    if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                        for key in ("stream", "index", "token"):
                            if key in chunk.meta:
                                entry[key] = str(chunk.meta[key])
                    results.append(entry)
                if len(results) >= limit:
                    break
            return results

        results = await asyncio.to_thread(_run_strings)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "filepath": state.filepath,
            "strings_found": len(results),
            "results": results,
        }, "refinery_dotnet")

    # ── blobs: binary items with optional text ──────────────────────
    if op == "blobs":
        def _run_blobs():
            import importlib
            mod = importlib.import_module(mod_path)
            unit_cls = getattr(mod, cls_name)
            results = []
            for chunk in data | unit_cls():
                raw = bytes(chunk)
                entry: Dict[str, Any] = {
                    "size": len(raw),
                    "hex": _bytes_to_hex(raw, 256),
                }
                if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                    for key in ("index", "token"):
                        if key in chunk.meta:
                            entry[key] = str(chunk.meta[key])
                text = _safe_decode(raw)
                if len(raw) < 256 and all(c.isprintable() or c in "\n\r\t" for c in text):
                    entry["text"] = text
                results.append(entry)
                if len(results) >= limit:
                    break
            return results

        results = await asyncio.to_thread(_run_blobs)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "filepath": state.filepath,
            "blobs_found": len(results),
            "results": results,
        }, "refinery_dotnet")

    # ── fields: constant values ─────────────────────────────────────
    if op == "fields":
        def _run_fields():
            import importlib
            mod = importlib.import_module(mod_path)
            unit_cls = getattr(mod, cls_name)
            results = []
            for chunk in data | unit_cls():
                raw = bytes(chunk)
                entry: Dict[str, Any] = {"size": len(raw)}
                if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                    for key in ("name", "type", "class", "token"):
                        if key in chunk.meta:
                            entry[key] = str(chunk.meta[key])
                text = _safe_decode(raw)
                if len(raw) < 512 and all(c.isprintable() or c in "\n\r\t\x00" for c in text):
                    entry["value_text"] = text.rstrip("\x00")
                else:
                    entry["value_hex"] = _bytes_to_hex(raw, 256)
                results.append(entry)
                if len(results) >= limit:
                    break
            return results

        results = await asyncio.to_thread(_run_fields)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "filepath": state.filepath,
            "fields_found": len(results),
            "results": results,
        }, "refinery_dotnet")

    # ── resources / managed_resources / arrays / sfx: binary items ──
    save_data = bool(output_path) and op in ("resources", "arrays", "sfx")

    def _run_multi():
        import importlib
        mod = importlib.import_module(mod_path)
        unit_cls = getattr(mod, cls_name)

        meta_keys = ("path", "name", "type")
        if op == "arrays":
            meta_keys = ("name", "token", "type")

        results = []
        raw_items: Optional[List[bytes]] = [] if save_data else None
        for chunk in data | unit_cls():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                for key in meta_keys:
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            if raw[:2] == b"MZ":
                entry["detected_type"] = "Embedded PE"
            elif raw[:4] == b"PK\x03\x04":
                entry["detected_type"] = "Embedded ZIP"
            if op == "arrays":
                entry["hex"] = _bytes_to_hex(raw, 512)
            else:
                entry["preview_hex"] = raw[:64].hex()
            results.append(entry)
            if raw_items is not None:
                raw_items.append(raw)
            if len(results) >= limit:
                break
        return results, raw_items

    results, raw_items = await asyncio.to_thread(_run_multi)

    count_key = {
        "resources": "resources_found",
        "managed_resources": "items_found",
        "arrays": "arrays_found",
        "sfx": "files_extracted",
    }.get(op, "items_found")

    response: Dict[str, Any] = {
        "operation": op,
        "filepath": state.filepath,
        count_key: len(results),
        "results": results,
    }
    if output_path and raw_items:
        from pathlib import Path
        state.check_path_allowed(str(Path(output_path).resolve()))
        os.makedirs(output_path, exist_ok=True)
        artifacts: List[Dict[str, Any]] = []
        seen_names: set = set()
        for i, raw in enumerate(raw_items):
            name = results[i].get("path") or results[i].get("name") or f"file_{i}.bin"
            name = os.path.basename(name) or f"file_{i}.bin"
            # Deduplicate filenames
            base_name = name
            counter = 1
            while name in seen_names:
                stem, ext = os.path.splitext(base_name)
                name = f"{stem}_{counter}{ext}"
                counter += 1
            seen_names.add(name)
            item_path = os.path.join(output_path, name)
            artifact_meta = await asyncio.to_thread(
                _write_output_and_register_artifact,
                item_path, raw, "refinery_dotnet",
                f"Extracted .NET {op}: {name} ({len(raw)} bytes)",
            )
            artifacts.append(artifact_meta)
        response["artifacts"] = artifacts
    return await _check_mcp_response_size(ctx, response, "refinery_dotnet")
