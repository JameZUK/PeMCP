"""MCP tools powered by Binary Refinery for forensic analysis.

Covers network forensics (PCAP parsing, HTTP extraction), Windows forensics
(Event Logs, Registry hives, LNK shortcuts, minidumps), IOC defanging,
URL guard removal, and protocol buffer decoding.
"""
import asyncio
import hashlib

from typing import Dict, Any, Optional, List

from pemcp.config import state, logger, Context
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size
from pemcp.mcp._refinery_helpers import (
    _require_refinery, _safe_decode, _bytes_to_hex, _hex_to_bytes,
    _get_file_data, _get_data_from_hex_or_file,
    _MAX_INPUT_SIZE_LARGE as _MAX_INPUT_SIZE,
    _MAX_OUTPUT_ITEMS,
)


# ===================================================================
#  1. PCAP / NETWORK FORENSICS
# ===================================================================

@tool_decorator
async def refinery_parse_pcap(
    ctx: Context,
    data_hex: Optional[str] = None,
    limit: int = 200,
) -> Dict[str, Any]:
    """
    Parse PCAP files and reassemble TCP streams using Binary Refinery.

    Extracts reassembled TCP streams from packet capture files.
    Useful for analyzing network traffic from malware sandboxes.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) PCAP data as hex. If None, uses loaded file.
        limit: (int) Max streams to extract. Default 200.

    Returns:
        Dictionary with reassembled TCP stream data.
    """
    _require_refinery("refinery_parse_pcap")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    await ctx.info(f"Parsing PCAP ({len(data)} bytes)...")

    def _run():
        from refinery.units.formats.pcap import pcap
        results = []
        for chunk in data | pcap():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('src', 'dst', 'sport', 'dport', 'protocol', 'stream'):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            text = _safe_decode(raw)
            if text[:4] in ('HTTP', 'GET ', 'POST', 'PUT ', 'HEAD'):
                entry["preview_text"] = text[:500]
            else:
                entry["preview_hex"] = raw[:128].hex()
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "streams_found": len(results),
        "input_size": len(data),
        "results": results,
    }, "refinery_parse_pcap")


@tool_decorator
async def refinery_parse_pcap_http(
    ctx: Context,
    data_hex: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Extract HTTP requests and responses from PCAP files using Binary Refinery.

    Parses PCAP data and extracts HTTP transactions with headers, bodies,
    URLs, and methods. Particularly useful for malware C2 traffic analysis.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) PCAP data as hex. If None, uses loaded file.
        limit: (int) Max HTTP transactions to extract. Default 100.

    Returns:
        Dictionary with extracted HTTP transactions.
    """
    _require_refinery("refinery_parse_pcap_http")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    await ctx.info(f"Extracting HTTP from PCAP ({len(data)} bytes)...")

    def _run():
        from refinery.units.formats.pcap_http import pcap_http
        results = []
        for chunk in data | pcap_http():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
            }
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('url', 'method', 'status', 'content_type', 'host'):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            entry["body_preview"] = _safe_decode(raw)[:1000]
            entry["sha256"] = hashlib.sha256(raw).hexdigest()
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "http_transactions": len(results),
        "input_size": len(data),
        "results": results,
    }, "refinery_parse_pcap_http")


# ===================================================================
#  2. WINDOWS EVENT LOGS
# ===================================================================

@tool_decorator
async def refinery_parse_evtx(
    ctx: Context,
    data_hex: Optional[str] = None,
    limit: int = 500,
) -> Dict[str, Any]:
    """
    Parse Windows Event Log (.evtx) files using Binary Refinery.

    Extracts individual event records as XML from Windows Event Log files.
    Useful for forensic analysis of compromised systems.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) EVTX data as hex. If None, uses loaded file.
        limit: (int) Max events to extract. Default 500.

    Returns:
        Dictionary with extracted event records.
    """
    _require_refinery("refinery_parse_evtx")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    await ctx.info(f"Parsing EVTX ({len(data)} bytes)...")

    def _run():
        from refinery.units.formats.evtx import evtx
        # evtx uses @Unit.Requires('python-evtx') — if the package is
        # missing, instantiation raises RefineryImportMissing.
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
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('id', 'record', 'channel', 'provider'):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "events_found": len(results),
        "input_size": len(data),
        "results": results,
    }, "refinery_parse_evtx")


# ===================================================================
#  3. WINDOWS REGISTRY
# ===================================================================

@tool_decorator
async def refinery_parse_registry(
    ctx: Context,
    data_hex: Optional[str] = None,
    limit: int = 500,
) -> Dict[str, Any]:
    """
    Parse Windows Registry hive files using Binary Refinery.

    Extracts key/value pairs from registry hive files (SAM, SYSTEM,
    SOFTWARE, NTUSER.DAT, etc.). Essential for forensic triage.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Registry hive data as hex. If None, uses loaded file.
        limit: (int) Max entries to extract. Default 500.

    Returns:
        Dictionary with registry key/value entries.
    """
    _require_refinery("refinery_parse_registry")

    data = _get_data_from_hex_or_file(data_hex)
    if len(data) > _MAX_INPUT_SIZE:
        raise RuntimeError(f"Input too large ({len(data)} bytes).")

    await ctx.info(f"Parsing Windows Registry hive ({len(data)} bytes)...")

    def _run():
        from refinery.units.formats.winreg import winreg
        results = []
        for chunk in data | winreg():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
            }
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('path', 'name', 'type', 'key'):
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
        "entries_found": len(results),
        "input_size": len(data),
        "results": results,
    }, "refinery_parse_registry")


# ===================================================================
#  4. WINDOWS SHORTCUTS (LNK)
# ===================================================================

@tool_decorator
async def refinery_parse_lnk(
    ctx: Context,
    data_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Parse Windows shortcut (.lnk) files using Binary Refinery.

    Extracts target path, command-line arguments, working directory,
    icon location, and other metadata from LNK files. Malicious LNK
    files are commonly used in phishing attacks.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) LNK data as hex. If None, uses loaded file.

    Returns:
        Dictionary with parsed LNK metadata.
    """
    _require_refinery("refinery_parse_lnk")

    data = _get_data_from_hex_or_file(data_hex)
    await ctx.info(f"Parsing LNK file ({len(data)} bytes)...")

    def _run():
        from refinery.units.formats.lnk import lnk
        results = []
        for chunk in data | lnk():
            raw = bytes(chunk)
            entry: Dict[str, Any] = {
                "size": len(raw),
                "content": _safe_decode(raw)[:4000],
            }
            if hasattr(chunk, 'meta') and isinstance(chunk.meta, dict):
                for key in ('target', 'arguments', 'workdir', 'icon', 'description',
                            'path', 'name', 'type'):
                    if key in chunk.meta:
                        entry[key] = str(chunk.meta[key])
            results.append(entry)
        return results

    results = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "input_size": len(data),
        "results": results,
    }, "refinery_parse_lnk")


# ===================================================================
#  5. IOC DEFANGING
# ===================================================================

@tool_decorator
async def refinery_defang_iocs(
    ctx: Context,
    data_hex: str,
) -> Dict[str, Any]:
    """
    Defang indicators of compromise using Binary Refinery.

    Converts active IOCs into safe, non-clickable forms:
    - URLs: https://evil.com -> hxxps[:]//evil[.]com
    - IPs: 192.168.1.1 -> 192[.]168[.]1[.]1
    - Emails: user@evil.com -> user[@]evil[.]com

    This is useful for safely sharing IOCs in reports and communications.

    Args:
        ctx: The MCP Context object.
        data_hex: (str) Data containing IOCs as hex string.

    Returns:
        Dictionary with defanged text output.
    """
    _require_refinery("refinery_defang_iocs")

    try:
        data = _hex_to_bytes(data_hex)
    except (ValueError, TypeError):
        data = data_hex.encode("utf-8")

    await ctx.info(f"Defanging IOCs in {len(data)} bytes of data...")

    def _run():
        from refinery.units.pattern.defang import defang
        return data | defang() | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "input_size": len(data),
        "output_size": len(result),
        "defanged_text": _safe_decode(result)[:8000],
    }, "refinery_defang_iocs")


@tool_decorator
async def refinery_strip_url_guards(
    ctx: Context,
    data_hex: str,
) -> Dict[str, Any]:
    """
    Remove URL protection/rewriting wrappers from URLs using Binary Refinery.

    Strips URL guard services (Outlook SafeLinks, ProofPoint, Barracuda,
    Mimecast, etc.) to reveal the original destination URL. Essential for
    analyzing phishing emails where URLs are wrapped by security gateways.

    Args:
        ctx: The MCP Context object.
        data_hex: (str) Data containing guarded URLs as hex string.

    Returns:
        Dictionary with cleaned URL text.
    """
    _require_refinery("refinery_strip_url_guards")

    try:
        data = _hex_to_bytes(data_hex)
    except (ValueError, TypeError):
        data = data_hex.encode("utf-8")

    await ctx.info(f"Stripping URL guards from {len(data)} bytes...")

    def _run():
        from refinery.units.pattern.urlguards import urlguards
        return data | urlguards() | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "input_size": len(data),
        "output_size": len(result),
        "cleaned_text": _safe_decode(result)[:4000],
    }, "refinery_strip_url_guards")


# ===================================================================
#  6. PROTOCOL BUFFERS
# ===================================================================

@tool_decorator
async def refinery_parse_protobuf(
    ctx: Context,
    data_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Decode Protocol Buffer (protobuf) messages to JSON using Binary Refinery.

    Decodes raw protobuf binary data into a readable JSON structure without
    needing the .proto schema definition. Uses heuristic field detection.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) Protobuf data as hex. If None, uses loaded file.

    Returns:
        Dictionary with decoded protobuf structure.
    """
    _require_refinery("refinery_parse_protobuf")

    data = _get_data_from_hex_or_file(data_hex)
    await ctx.info(f"Decoding protobuf message ({len(data)} bytes)...")

    def _run():
        from refinery.units.formats.pbuf import pbuf
        return data | pbuf() | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "input_size": len(data),
        "output_size": len(result),
        "decoded_json": _safe_decode(result)[:8000],
    }, "refinery_parse_protobuf")


# ===================================================================
#  7. MESSAGEPACK
# ===================================================================

@tool_decorator
async def refinery_parse_msgpack(
    ctx: Context,
    data_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Decode MessagePack binary data to JSON using Binary Refinery.

    MessagePack is a compact binary serialization format used by many
    applications and some malware C2 protocols.

    Args:
        ctx: The MCP Context object.
        data_hex: (Optional[str]) MessagePack data as hex. If None, uses loaded file.

    Returns:
        Dictionary with decoded JSON structure.
    """
    _require_refinery("refinery_parse_msgpack")

    data = _get_data_from_hex_or_file(data_hex)
    await ctx.info(f"Decoding MessagePack ({len(data)} bytes)...")

    def _run():
        from refinery.units.formats.msgpack import msgpack
        return data | msgpack() | bytes

    result = await asyncio.to_thread(_run)
    return await _check_mcp_response_size(ctx, {
        "input_size": len(data),
        "output_size": len(result),
        "decoded_json": _safe_decode(result)[:8000],
    }, "refinery_parse_msgpack")
