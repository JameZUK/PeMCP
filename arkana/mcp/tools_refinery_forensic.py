"""MCP tools powered by Binary Refinery for forensic analysis.

Provides network forensics (PCAP, HTTP extraction), Windows forensics
(Event Logs, Registry hives, LNK shortcuts), IOC defanging, URL guard
removal, and protocol buffer / MessagePack decoding through a single
dispatched tool.
"""
import asyncio
import hashlib

from typing import Dict, Any, Optional

from arkana.config import state, logger, Context
from arkana.constants import MAX_TOOL_LIMIT
from arkana.mcp.server import tool_decorator, _check_mcp_response_size
from arkana.mcp._refinery_helpers import (
    _require_refinery, _safe_decode, _bytes_to_hex, _hex_to_bytes,
    _get_file_data, _get_data_from_hex_or_file,
    _MAX_INPUT_SIZE_LARGE as _MAX_INPUT_SIZE,
    _MAX_OUTPUT_ITEMS,
)


@tool_decorator
async def refinery_forensic(
    ctx: Context,
    operation: str,
    data_hex: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """Forensic analysis via Binary Refinery.

    Operations:
    - 'pcap': Parse PCAP and reassemble TCP streams.
    - 'pcap_http': Extract HTTP requests/responses from PCAP files.
    - 'evtx': Parse Windows Event Log (.evtx) files.
    - 'registry': Parse Windows Registry hive files (SAM, SYSTEM, NTUSER.DAT, etc.).
    - 'lnk': Parse Windows shortcut (.lnk) files.
    - 'defang': Defang IOCs (URLs, IPs, emails) for safe sharing.
    - 'url_guards': Remove URL protection wrappers (SafeLinks, ProofPoint, etc.).
    - 'protobuf': Decode Protocol Buffer messages to JSON (schema-less).
    - 'msgpack': Decode MessagePack binary data to JSON.

    Args:
        ctx: MCP Context.
        operation: (str) One of the operations listed above.
        data_hex: (Optional[str]) Input data as hex. If None, uses loaded file.
        limit: (int) Max items to return (where applicable). Default 20.

    Returns:
        Dictionary with operation-specific results.
    """
    _require_refinery("refinery_forensic")
    limit = max(1, min(limit, MAX_TOOL_LIMIT))

    op = operation.lower()

    _SUPPORTED = [
        "pcap", "pcap_http", "evtx", "registry", "lnk",
        "defang", "url_guards", "protobuf", "msgpack",
    ]
    if op not in _SUPPORTED:
        return {"error": f"Unknown operation '{operation}'.", "supported": sorted(_SUPPORTED)}

    # ── defang / url_guards accept text directly ────────────────────
    if op in ("defang", "url_guards"):
        if data_hex:
            try:
                data = _hex_to_bytes(data_hex)
            except (ValueError, TypeError):
                data = data_hex.encode("utf-8")
        else:
            data = _get_file_data()

        await ctx.info(f"Forensic operation: {op} ({len(data)} bytes)")

        if op == "defang":
            def _run_defang():
                from refinery.units.pattern.defang import defang
                return data | defang() | bytes
            result = await asyncio.to_thread(_run_defang)
            return await _check_mcp_response_size(ctx, {
                "operation": op,
                "input_size": len(data),
                "output_size": len(result),
                "defanged_text": _safe_decode(result, max_len=8000),
            }, "refinery_forensic")
        else:  # url_guards
            def _run_urlguards():
                from refinery.units.pattern.urlguards import urlguards
                return data | urlguards() | bytes
            result = await asyncio.to_thread(_run_urlguards)
            return await _check_mcp_response_size(ctx, {
                "operation": op,
                "input_size": len(data),
                "output_size": len(result),
                "cleaned_text": _safe_decode(result, max_len=4000),
            }, "refinery_forensic")

    # ── All other operations get data from hex or file ──────────────
    data = _get_data_from_hex_or_file(data_hex)
    if op not in ("lnk",) and len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    await ctx.info(f"Forensic operation: {op} ({len(data)} bytes)")

    # ── protobuf / msgpack: single-output decode ────────────────────
    if op in ("protobuf", "msgpack"):
        _DECODE_MAP = {
            "protobuf": "refinery.units.formats.pbuf:pbuf",
            "msgpack":  "refinery.units.formats.msgpack:msgpack",
        }
        mod_path, cls_name = _DECODE_MAP[op].rsplit(":", 1)

        def _run_decode():
            import importlib
            mod = importlib.import_module(mod_path)
            unit_cls = getattr(mod, cls_name)
            return data | unit_cls() | bytes

        result = await asyncio.to_thread(_run_decode)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "input_size": len(data),
            "output_size": len(result),
            "decoded_json": _safe_decode(result, max_len=8000),
        }, "refinery_forensic")

    # ── pcap: TCP stream reassembly ─────────────────────────────────
    if op == "pcap":
        def _run_pcap():
            from refinery.units.formats.pcap import pcap
            results = []
            for chunk in data | pcap():
                raw = bytes(chunk)
                entry: Dict[str, Any] = {
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
                if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                    for key in ("src", "dst", "sport", "dport", "protocol", "stream"):
                        if key in chunk.meta:
                            entry[key] = str(chunk.meta[key])
                text = _safe_decode(raw)
                if text[:4] in ("HTTP", "GET ", "POST", "PUT ", "HEAD"):
                    entry["preview_text"] = text[:500]
                else:
                    entry["preview_hex"] = raw[:128].hex()
                results.append(entry)
                if len(results) >= limit:
                    break
            return results

        results = await asyncio.to_thread(_run_pcap)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "streams_found": len(results),
            "input_size": len(data),
            "results": results,
        }, "refinery_forensic")

    # ── pcap_http: HTTP transaction extraction ──────────────────────
    if op == "pcap_http":
        def _run_pcap_http():
            from refinery.units.formats.pcap_http import pcap_http
            results = []
            for chunk in data | pcap_http():
                raw = bytes(chunk)
                entry: Dict[str, Any] = {"size": len(raw)}
                if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                    for key in ("url", "method", "status", "content_type", "host"):
                        if key in chunk.meta:
                            entry[key] = str(chunk.meta[key])
                entry["body_preview"] = _safe_decode(raw, max_len=1000)
                entry["sha256"] = hashlib.sha256(raw).hexdigest()
                results.append(entry)
                if len(results) >= limit:
                    break
            return results

        results = await asyncio.to_thread(_run_pcap_http)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "http_transactions": len(results),
            "input_size": len(data),
            "results": results,
        }, "refinery_forensic")

    # ── evtx: Windows Event Log parsing ─────────────────────────────
    if op == "evtx":
        def _run_evtx():
            from refinery.units.formats.evtx import evtx
            try:
                unit = evtx()
            except Exception as e:
                if "python-evtx" in str(e) or "Missing" in type(e).__name__:
                    raise RuntimeError(
                        "evtx parsing requires the 'python-evtx' package. "
                        "Install it with: pip install python-evtx"
                    ) from e
                raise
            results = []
            for chunk in data | unit:
                raw = bytes(chunk)
                text = _safe_decode(raw)
                entry: Dict[str, Any] = {
                    "size": len(raw),
                    "event_xml": text[:2000],
                }
                if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                    for key in ("id", "record", "channel", "provider"):
                        if key in chunk.meta:
                            entry[key] = str(chunk.meta[key])
                results.append(entry)
                if len(results) >= limit:
                    break
            return results

        results = await asyncio.to_thread(_run_evtx)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "events_found": len(results),
            "input_size": len(data),
            "results": results,
        }, "refinery_forensic")

    # ── registry: Windows Registry hive parsing ─────────────────────
    if op == "registry":
        def _run_registry():
            from refinery.units.formats.winreg import winreg
            results = []
            for chunk in data | winreg():
                raw = bytes(chunk)
                entry: Dict[str, Any] = {"size": len(raw)}
                if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                    for key in ("path", "name", "type", "key"):
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

        results = await asyncio.to_thread(_run_registry)
        return await _check_mcp_response_size(ctx, {
            "operation": op,
            "entries_found": len(results),
            "input_size": len(data),
            "results": results,
        }, "refinery_forensic")

    # ── lnk: Windows shortcut parsing ───────────────────────────────
    # op == "lnk"
    def _run_lnk():
        from refinery.units.formats.lnk import lnk
        results = []
        for chunk in data | lnk():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
                "content": _safe_decode(raw, max_len=4000),
            }
            if hasattr(chunk, "meta") and isinstance(chunk.meta, dict):
                for key in ("target", "arguments", "workdir", "icon", "description",
                            "path", "name", "type"):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run_lnk)
    return await _check_mcp_response_size(ctx, {
        "operation": op,
        "input_size": len(data),
        "results": results,
    }, "refinery_forensic")
