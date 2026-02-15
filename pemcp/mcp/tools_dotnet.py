"""MCP tools for .NET binary analysis using dnfile and dncil."""
import asyncio
from typing import Dict, Any, Optional
from pemcp.config import state, logger, Context, DNFILE_AVAILABLE, DNCIL_AVAILABLE
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size
from pemcp.mcp._format_helpers import _check_lib, _get_filepath

if DNFILE_AVAILABLE:
    import dnfile
if DNCIL_AVAILABLE:
    from dncil.cil.body import CilMethodBody
    from dncil.cil.error import CilError
    from dncil.clr.token import Token


@tool_decorator
async def dotnet_analyze(
    ctx: Context,
    file_path: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Comprehensive .NET assembly analysis: CLR header, metadata streams,
    type definitions, method definitions, assembly references, and user strings.

    Args:
        file_path: Optional path to a .NET binary. If None, uses the loaded file.
        limit: Max entries per category.
    """
    await ctx.info("Analysing .NET metadata")
    _check_lib("dnfile", DNFILE_AVAILABLE, "dotnet_analyze")
    target = _get_filepath(file_path)

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
            has_metadata_tables = (
                has_clr_header
                and hasattr(clr, 'mdtables')
                and clr.mdtables is not None
            )

            if not has_clr_header:
                dn.close()
                return {"error": "Not a valid .NET binary or parsing failed: 'File is not a .NET assembly.'"}

            result: Dict[str, Any] = {"file": target, "is_dotnet": True}

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
    return await _check_mcp_response_size(ctx, result, "dotnet_analyze", "the 'limit' parameter")


@tool_decorator
async def dotnet_disassemble_method(
    ctx: Context,
    method_rva: str,
    file_path: Optional[str] = None,
    limit: int = 200,
) -> Dict[str, Any]:
    """
    Disassembles a .NET method's CIL bytecode into human-readable opcodes.

    Args:
        method_rva: Hex RVA of the method (from dotnet_analyze's method_definitions).
        file_path: Optional path. If None, uses the loaded file.
        limit: Max CIL instructions to return.
    """
    await ctx.info(f"Disassembling .NET method at {method_rva}")
    _check_lib("dnfile", DNFILE_AVAILABLE, "dotnet_disassemble_method")
    _check_lib("dncil", DNCIL_AVAILABLE, "dotnet_disassemble_method")
    target = _get_filepath(file_path)

    rva = int(method_rva, 16)

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
