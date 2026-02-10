"""MCP tools for Mach-O binary analysis using LIEF."""
import asyncio
from typing import Dict, Any, Optional
from pemcp.config import state, logger, Context
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size
from pemcp.mcp._format_helpers import _check_lib, _get_filepath

LIEF_AVAILABLE = False
try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    pass


@tool_decorator
async def macho_analyze(
    ctx: Context,
    file_path: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Analyses a Mach-O binary: header, load commands, segments, sections,
    symbols, dynamic libraries, and code signature info.

    Args:
        file_path: Optional path to a Mach-O binary. If None, uses the loaded file.
        limit: Max entries per category.
    """
    await ctx.info("Analysing Mach-O binary")
    _check_lib("lief", LIEF_AVAILABLE, "macho_analyze")
    target = _get_filepath(file_path)

    def _parse():
        binary = lief.parse(target)
        if binary is None:
            return {"error": f"LIEF could not parse {target}"}

        # Check if it's actually Mach-O
        if binary.format != lief.Binary.FORMATS.MACHO:
            return {"error": f"Not a Mach-O binary (detected format: {str(binary.format).split('.')[-1]})"}

        macho = binary
        result: Dict[str, Any] = {"file": target, "is_macho": True}

        # Header
        header = macho.header
        result["header"] = {
            "magic": hex(header.magic) if hasattr(header, 'magic') else None,
            "cpu_type": str(header.cpu_type).split(".")[-1] if hasattr(header, 'cpu_type') else None,
            "file_type": str(header.file_type).split(".")[-1] if hasattr(header, 'file_type') else None,
            "number_of_commands": header.nb_cmds if hasattr(header, 'nb_cmds') else None,
            "flags": hex(header.flags) if hasattr(header, 'flags') else None,
        }

        # Load commands
        commands = []
        try:
            for cmd in macho.commands:
                cmd_entry = {
                    "type": str(cmd.command).split(".")[-1] if hasattr(cmd, 'command') else str(type(cmd).__name__),
                    "size": cmd.size if hasattr(cmd, 'size') else None,
                }
                commands.append(cmd_entry)
                if len(commands) >= limit:
                    break
        except Exception:
            pass
        result["load_commands"] = commands

        # Segments and sections
        segments = []
        try:
            for seg in macho.segments:
                sections = []
                for sec in seg.sections:
                    sections.append({
                        "name": sec.name,
                        "size": sec.size,
                        "offset": sec.offset,
                        "entropy": round(sec.entropy, 4) if hasattr(sec, 'entropy') else None,
                    })
                segments.append({
                    "name": seg.name,
                    "virtual_address": hex(seg.virtual_address),
                    "virtual_size": seg.virtual_size,
                    "file_size": seg.file_size,
                    "max_protection": seg.max_protection,
                    "init_protection": seg.init_protection,
                    "sections": sections,
                })
                if len(segments) >= limit:
                    break
        except Exception:
            pass
        result["segments"] = segments

        # Symbols
        symbols = []
        try:
            for sym in macho.symbols:
                if sym.name:
                    symbols.append({
                        "name": sym.name,
                        "value": hex(sym.value) if hasattr(sym, 'value') else None,
                        "type": sym.type if hasattr(sym, 'type') else None,
                    })
                    if len(symbols) >= limit:
                        break
        except Exception:
            pass
        result["symbols"] = symbols

        # Dynamic libraries
        dylibs = []
        try:
            for lib in macho.libraries:
                dylibs.append({
                    "name": lib.name,
                    "version": f"{lib.current_version[0]}.{lib.current_version[1]}.{lib.current_version[2]}" if hasattr(lib, 'current_version') else None,
                })
                if len(dylibs) >= limit:
                    break
        except Exception:
            pass
        result["dynamic_libraries"] = dylibs

        # Code signature
        try:
            if hasattr(macho, 'code_signature') and macho.code_signature:
                cs = macho.code_signature
                result["code_signature"] = {
                    "data_offset": cs.data_offset if hasattr(cs, 'data_offset') else None,
                    "data_size": cs.data_size if hasattr(cs, 'data_size') else None,
                }
        except Exception:
            pass

        # Entrypoint
        try:
            result["entrypoint"] = hex(macho.entrypoint)
        except Exception:
            pass

        result["summary"] = {
            "load_commands": len(commands),
            "segments": len(segments),
            "symbols": len(symbols),
            "dynamic_libraries": len(dylibs),
        }

        return result

    result = await asyncio.to_thread(_parse)
    return await _check_mcp_response_size(ctx, result, "macho_analyze", "the 'limit' parameter")
