"""MCP tools for .NET binary analysis using dnfile, dncil, and dotnetfile."""
import asyncio
import os
from typing import Dict, Any, Optional, List
from arkana.config import state, logger, Context, DNFILE_AVAILABLE, DNCIL_AVAILABLE, DOTNETFILE_AVAILABLE
from arkana.mcp.server import tool_decorator, _check_mcp_response_size
from arkana.mcp._format_helpers import _check_lib, _get_filepath
from arkana.constants import MAX_TOOL_LIMIT

if DNFILE_AVAILABLE:
    import dnfile
if DNCIL_AVAILABLE:
    from dncil.cil.body import CilMethodBody
    from dncil.cil.error import MethodBodyFormatError as CilError
    from dncil.clr.token import Token
if DOTNETFILE_AVAILABLE:
    import dotnetfile


@tool_decorator
async def dotnet_analyze(
    ctx: Context,
    file_path: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: triage] Comprehensive .NET assembly analysis: CLR header, metadata
    streams, type definitions, method definitions, member references, assembly
    references, and user strings. Uses dnfile backend when available, falls back
    to dotnetfile automatically.

    When to use: When detect_binary_format() or classify_binary_purpose()
    identifies a .NET assembly. For resource extraction and CIL disassembly,
    use refinery_dotnet().

    Next steps: dotnet_disassemble_method() to inspect specific methods,
    get_triage_report() for risk assessment, extract_wide_strings() for
    .NET wide string data.

    See also: refinery_dotnet() (Binary Refinery).

    Args:
        file_path: Optional path to a .NET binary. If None, uses the loaded file.
        limit: Max entries per category.
    """
    await ctx.info("Analysing .NET metadata")
    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    if not DNFILE_AVAILABLE and not DOTNETFILE_AVAILABLE:
        return {"error": "Neither dnfile nor dotnetfile is installed. Install one: pip install dnfile  OR  pip install dotnetfile"}
    target = _get_filepath(file_path)

    # Use dotnetfile fallback if dnfile is not available
    if not DNFILE_AVAILABLE:
        await ctx.info("dnfile not available, using dotnetfile backend")
        result = await asyncio.to_thread(_parse_with_dotnetfile, target, limit)
        result["backend"] = "dotnetfile"
        return await _check_mcp_response_size(ctx, result, "dotnet_analyze", "the 'limit' parameter")

    def _parse():
        try:
            dn = dnfile.dnPE(target)
        except Exception as e:
            return {"error": f"Not a valid .NET binary or parsing failed: {e}"}

        try:
            # Verify this is actually a .NET binary by checking for a valid
            # CLR header.  dnfile.dnPE() silently opens non-.NET PEs without
            # raising, leaving .net as None or with an empty metadata table.
            clr = getattr(dn, 'net', None)
            has_clr_header = (
                clr is not None
                and hasattr(clr, 'struct')
                and clr.struct is not None
            )
            if not has_clr_header:
                dn.close()
                return {"error": "Not a valid .NET binary or parsing failed: 'File is not a .NET assembly.'"}

            result: Dict[str, Any] = {"file": os.path.basename(target), "is_dotnet": True}

            # CLR header
            try:
                if clr:
                    result["clr_header"] = {
                        "runtime_version": f"{clr.struct.MajorRuntimeVersion}.{clr.struct.MinorRuntimeVersion}",
                        "flags": hex(clr.struct.Flags) if hasattr(clr.struct, 'Flags') else None,
                        "entry_point_token": hex(clr.struct.EntryPointTokenOrRva) if hasattr(clr.struct, 'EntryPointTokenOrRva') else None,
                    }
                    # Metadata header
                    if hasattr(clr, 'metadata') and clr.metadata:
                        md = clr.metadata
                        result["metadata_header"] = {
                            "version": md.struct.Version.decode('utf-8', 'ignore').strip('\x00') if hasattr(md.struct, 'Version') else None,
                        }
                        # Streams
                        streams = []
                        if hasattr(md, 'streams_list'):
                            for s in md.streams_list:
                                streams.append({
                                    "name": s.struct.Name.decode('utf-8', 'ignore').strip('\x00') if hasattr(s.struct, 'Name') else str(s),
                                    "offset": getattr(s.struct, 'Offset', None),
                                    "size": getattr(s.struct, 'Size', None),
                                })
                        result["metadata_streams"] = streams
            except Exception as e:
                result["clr_header_error"] = str(e)

            # TypeDef table
            types = []
            try:
                if hasattr(dn.net, 'mdtables') and dn.net.mdtables:
                    td_table = dn.net.mdtables.TypeDef
                    if td_table and hasattr(td_table, 'rows'):
                        for row in td_table.rows:
                            types.append({
                                "name": str(row.TypeName) if hasattr(row, 'TypeName') else None,
                                "namespace": str(row.TypeNamespace) if hasattr(row, 'TypeNamespace') else None,
                                "flags": hex(row.Flags) if hasattr(row, 'Flags') else None,
                            })
                            if len(types) >= limit:
                                break
            except Exception:
                pass
            result["type_definitions"] = types

            # MethodDef table
            methods = []
            try:
                if hasattr(dn.net, 'mdtables') and dn.net.mdtables:
                    md_table = dn.net.mdtables.MethodDef
                    if md_table and hasattr(md_table, 'rows'):
                        for row in md_table.rows:
                            methods.append({
                                "name": str(row.Name) if hasattr(row, 'Name') else None,
                                "rva": hex(row.Rva) if hasattr(row, 'Rva') else None,
                                "flags": hex(row.Flags) if hasattr(row, 'Flags') else None,
                                "impl_flags": hex(row.ImplFlags) if hasattr(row, 'ImplFlags') else None,
                            })
                            if len(methods) >= limit:
                                break
            except Exception:
                pass
            result["method_definitions"] = methods
            if len(methods) >= limit:
                result["method_definitions_truncated"] = True
                result["method_definitions_total_hint"] = f"Results capped at {limit}. Use limit parameter to see more."

            # AssemblyRef table
            refs = []
            try:
                if hasattr(dn.net, 'mdtables') and dn.net.mdtables:
                    ar_table = dn.net.mdtables.AssemblyRef
                    if ar_table and hasattr(ar_table, 'rows'):
                        for row in ar_table.rows:
                            refs.append({
                                "name": str(row.Name) if hasattr(row, 'Name') else None,
                                "version": f"{row.MajorVersion}.{row.MinorVersion}.{row.BuildNumber}.{row.RevisionNumber}" if hasattr(row, 'MajorVersion') else None,
                            })
                            if len(refs) >= limit:
                                break
            except Exception:
                pass
            result["assembly_references"] = refs

            # MemberRef table (API calls)
            memberrefs = []
            try:
                if hasattr(dn.net, 'mdtables') and dn.net.mdtables:
                    mr_table = dn.net.mdtables.MemberRef
                    if mr_table and hasattr(mr_table, 'rows'):
                        for row in mr_table.rows:
                            memberrefs.append({
                                "name": str(row.Name) if hasattr(row, 'Name') else None,
                                "class": str(row.Class.row.TypeName) if hasattr(row, 'Class') and hasattr(row.Class, 'row') and hasattr(row.Class.row, 'TypeName') else None,
                            })
                            if len(memberrefs) >= limit:
                                break
            except Exception:
                pass
            result["member_references"] = memberrefs

            # User strings
            user_strings = []
            try:
                us = dn.net.user_strings
                if us:
                    for s in us:
                        if s and len(str(s)) > 1:
                            user_strings.append(str(s))
                        if len(user_strings) >= limit:
                            break
            except Exception:
                pass
            result["user_strings"] = user_strings

            # Summary counts
            result["summary"] = {
                "types": len(types),
                "methods": len(methods),
                "assembly_refs": len(refs),
                "member_refs": len(memberrefs),
                "user_strings": len(user_strings),
            }

            return result
        finally:
            dn.close()

    result = await asyncio.to_thread(_parse)
    if "error" not in result:
        result["backend"] = "dnfile"
    return await _check_mcp_response_size(ctx, result, "dotnet_analyze", "the 'limit' parameter")


def _parse_with_dotnetfile(target: str, limit: int) -> Dict[str, Any]:
    """Parse .NET metadata using the dotnetfile backend (fallback)."""
    try:
        dn = dotnetfile.DotNetPE(target)
    except Exception as e:
        return {"error": f"Not a valid .NET binary or parsing failed: {e}"}

    result: Dict[str, Any] = {"file": os.path.basename(target), "is_dotnet": True}

    # CLR header
    try:
        result["clr_header"] = {
            "runtime_version": str(dn.clr_header.RuntimeVersion) if hasattr(dn, 'clr_header') else None,
        }
    except Exception as e:
        logger.debug("Could not read CLR version: %s", e)

    # Type definitions
    types: List[Dict[str, Any]] = []
    try:
        for td in dn.metadata_table_lookup("TypeDef"):
            types.append({
                "name": str(td.TypeName),
                "namespace": str(td.TypeNamespace),
            })
            if len(types) >= limit:
                break
    except Exception as e:
        logger.debug("Error reading .NET TypeDef table: %s", e)
    result["type_definitions"] = types

    # Method definitions
    methods: List[Dict[str, Any]] = []
    try:
        for md in dn.metadata_table_lookup("MethodDef"):
            methods.append({
                "name": str(md.Name),
                "rva": hex(md.RVA) if md.RVA else None,
            })
            if len(methods) >= limit:
                break
    except Exception as e:
        logger.debug("Error reading .NET MethodDef table: %s", e)
    result["method_definitions"] = methods
    if len(methods) >= limit:
        result["method_definitions_truncated"] = True
        result["method_definitions_total_hint"] = f"Results capped at {limit}. Use limit parameter to see more."

    # Assembly references
    refs: List[Dict[str, Any]] = []
    try:
        for ref in dn.metadata_table_lookup("AssemblyRef"):
            refs.append({
                "name": str(ref.Name),
                "version": f"{ref.MajorVersion}.{ref.MinorVersion}" if hasattr(ref, 'MajorVersion') else None,
            })
            if len(refs) >= limit:
                break
    except Exception as e:
        logger.debug("Error reading .NET AssemblyRef table: %s", e)
    result["assembly_references"] = refs

    # User strings
    user_strings: List[str] = []
    try:
        for s in dn.get_user_strings():
            if s and len(s) > 2:
                user_strings.append(str(s))
            if len(user_strings) >= limit:
                break
    except Exception as e:
        logger.debug("Error reading .NET user strings: %s", e)
    result["user_strings"] = user_strings

    # Summary
    result["summary"] = {
        "types": len(types),
        "methods": len(methods),
        "assembly_refs": len(refs),
        "user_strings": len(user_strings),
    }

    return result


@tool_decorator
async def dotnet_disassemble_method(
    ctx: Context,
    method_rva: str,
    file_path: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    [Phase: deep-dive] Disassembles a .NET method's CIL bytecode into
    human-readable opcodes.

    When to use: After dotnet_analyze() identified interesting methods. Use
    the method_rva from dotnet_analyze()'s method_definitions output.

    Next steps: add_note() to record method behavior, auto_note_function()
    with a custom_summary for the .NET method.

    Args:
        method_rva: Hex or decimal RVA of the method (from dotnet_analyze's method_definitions).
        file_path: Optional path. If None, uses the loaded file.
        limit: Max CIL instructions to return.
    """
    await ctx.info(f"Disassembling .NET method at {method_rva}")
    _check_lib("dnfile", DNFILE_AVAILABLE, "dotnet_disassemble_method")
    _check_lib("dncil", DNCIL_AVAILABLE, "dotnet_disassemble_method")
    target = _get_filepath(file_path)

    rva = int(method_rva, 0)

    def _disasm():
        try:
            dn = dnfile.dnPE(target)
        except Exception as e:
            return {"error": f"Failed to parse .NET binary: {e}"}

        try:
            # Get the raw data at the method RVA
            try:
                offset = dn.get_offset_from_rva(rva)
            except Exception:
                return {"error": f"Could not resolve RVA {hex(rva)} to file offset."}

            try:
                data = dn.__data__[offset:]
                body = CilMethodBody(data)
            except CilError as e:
                return {"error": f"Failed to parse CIL method body: {e}"}
            except Exception as e:
                return {"error": f"CIL parsing error: {e}"}

            instructions = []
            for insn in body.instructions:
                entry = {
                    "offset": hex(insn.offset),
                    "opcode": str(insn.opcode),
                    "operand": str(insn.operand) if insn.operand is not None else None,
                    "size": insn.size,
                }
                instructions.append(entry)
                if len(instructions) >= limit:
                    break

            result = {
                "method_rva": hex(rva),
                "header_size": body.header_size if hasattr(body, 'header_size') else None,
                "max_stack": body.max_stack if hasattr(body, 'max_stack') else None,
                "code_size": body.code_size if hasattr(body, 'code_size') else None,
                "local_var_sig_tok": hex(body.local_var_sig_tok) if hasattr(body, 'local_var_sig_tok') and body.local_var_sig_tok else None,
                "instruction_count": len(instructions),
                "instructions": instructions,
            }

            # Exception handlers
            if hasattr(body, 'exception_handlers') and body.exception_handlers:
                handlers = []
                for eh in body.exception_handlers:
                    handlers.append({
                        "type": str(eh.clause_type) if hasattr(eh, 'clause_type') else None,
                        "try_offset": hex(eh.try_offset) if hasattr(eh, 'try_offset') else None,
                        "handler_offset": hex(eh.handler_offset) if hasattr(eh, 'handler_offset') else None,
                    })
                result["exception_handlers"] = handlers

            return result
        finally:
            dn.close()

    result = await asyncio.to_thread(_disasm)
    return await _check_mcp_response_size(ctx, result, "dotnet_disassemble_method", "the 'limit' parameter")
