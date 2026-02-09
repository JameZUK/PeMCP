"""MCP tools for multi-format binary analysis — .NET, Go, Rust, ELF, and Mach-O."""
import asyncio
import os
import struct

from typing import Dict, Any, Optional, List

from pemcp.config import state, logger, Context
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size

# ---------------------------------------------------------------------------
#  Optional library availability flags
# ---------------------------------------------------------------------------

DNFILE_AVAILABLE = False
try:
    import dnfile
    DNFILE_AVAILABLE = True
except ImportError:
    pass

DNCIL_AVAILABLE = False
try:
    from dncil.cil.body import CilMethodBody
    from dncil.cil.error import CilError
    from dncil.clr.token import Token
    DNCIL_AVAILABLE = True
except ImportError:
    pass

PYGORE_AVAILABLE = False
try:
    import pygore
    PYGORE_AVAILABLE = True
except ImportError:
    pass

RUSTBININFO_AVAILABLE = False
try:
    import rustbininfo
    RUSTBININFO_AVAILABLE = True
except ImportError:
    pass

RUST_DEMANGLER_AVAILABLE = False
try:
    import rust_demangler
    RUST_DEMANGLER_AVAILABLE = True
except ImportError:
    pass

PYELFTOOLS_AVAILABLE = False
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    pass

LIEF_AVAILABLE = False
try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    pass


def _check_lib(lib_name: str, available: bool, tool_name: str, pip_name: str = None):
    if not available:
        pkg = pip_name or lib_name
        raise RuntimeError(
            f"[{tool_name}] The '{lib_name}' library is not installed. "
            f"Install with: pip install {pkg}"
        )


def _get_filepath(file_path: Optional[str] = None) -> str:
    target = file_path or state.filepath
    if not target or not os.path.isfile(target):
        raise RuntimeError("No file specified and no file is loaded. Use open_file() first.")
    return target


# ===================================================================
#  .NET ANALYSIS — dnfile + dncil
# ===================================================================

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

        result: Dict[str, Any] = {"file": target, "is_dotnet": True}

        # CLR header
        try:
            clr = dn.net
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

        dn.close()
        return result

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

        dn.close()
        return result

    result = await asyncio.to_thread(_disasm)
    return await _check_mcp_response_size(ctx, result, "dotnet_disassemble_method", "the 'limit' parameter")


# ===================================================================
#  GO BINARY ANALYSIS — pygore
# ===================================================================

@tool_decorator
async def go_analyze(
    ctx: Context,
    file_path: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Analyses a Go binary: compiler version, packages, function names with addresses,
    type definitions. Works on stripped binaries by parsing pclntab.

    Args:
        file_path: Optional path to a Go binary. If None, uses the loaded file.
        limit: Max entries per category.
    """
    await ctx.info("Analysing Go binary")
    _check_lib("pygore", PYGORE_AVAILABLE, "go_analyze")
    target = _get_filepath(file_path)

    def _parse():
        try:
            f = pygore.GoFile(target)
        except Exception as e:
            return {"error": f"Not a Go binary or pygore parsing failed: {e}"}

        result: Dict[str, Any] = {"file": target, "is_go_binary": True}

        # Compiler version
        try:
            result["compiler_version"] = f.get_compiler_version()
        except Exception:
            result["compiler_version"] = None

        # Build ID
        try:
            result["build_id"] = f.get_build_id() if hasattr(f, 'get_build_id') else None
        except Exception:
            result["build_id"] = None

        # Packages
        packages = []
        try:
            for pkg in f.get_packages():
                funcs = []
                for fn in (pkg.functions or []):
                    funcs.append({
                        "name": fn.name if hasattr(fn, 'name') else str(fn),
                        "offset": fn.offset if hasattr(fn, 'offset') else None,
                        "end": fn.end if hasattr(fn, 'end') else None,
                    })

                methods = []
                for m in (pkg.methods or []):
                    methods.append({
                        "receiver": m.receiver if hasattr(m, 'receiver') else None,
                        "name": m.name if hasattr(m, 'name') else str(m),
                        "offset": m.offset if hasattr(m, 'offset') else None,
                    })

                packages.append({
                    "name": pkg.name if hasattr(pkg, 'name') else str(pkg),
                    "function_count": len(funcs),
                    "method_count": len(methods),
                    "functions": funcs[:20],
                    "methods": methods[:20],
                })
                if len(packages) >= limit:
                    break
        except Exception as e:
            result["packages_error"] = str(e)
        result["packages"] = packages

        # Vendor packages (third-party dependencies)
        vendor_pkgs = []
        try:
            for pkg in f.get_vendor_packages():
                vendor_funcs = []
                for fn in (pkg.functions or []):
                    vendor_funcs.append({
                        "name": fn.name if hasattr(fn, 'name') else str(fn),
                        "offset": fn.offset if hasattr(fn, 'offset') else None,
                    })
                vendor_pkgs.append({
                    "name": pkg.name if hasattr(pkg, 'name') else str(pkg),
                    "function_count": len(vendor_funcs),
                    "functions": vendor_funcs[:10],
                })
                if len(vendor_pkgs) >= limit:
                    break
        except Exception:
            pass
        result["vendor_packages"] = vendor_pkgs

        # Types
        types = []
        try:
            for t in f.get_types():
                types.append({
                    "name": t.name if hasattr(t, 'name') else str(t),
                    "kind": t.kind if hasattr(t, 'kind') else None,
                })
                if len(types) >= limit:
                    break
        except Exception:
            pass
        result["types"] = types

        result["summary"] = {
            "packages": len(packages),
            "vendor_packages": len(vendor_pkgs),
            "types": len(types),
        }

        f.close() if hasattr(f, 'close') else None
        return result

    result = await asyncio.to_thread(_parse)
    return await _check_mcp_response_size(ctx, result, "go_analyze", "the 'limit' parameter")


# ===================================================================
#  RUST BINARY ANALYSIS — rustbininfo + rust-demangler
# ===================================================================

@tool_decorator
async def rust_analyze(
    ctx: Context,
    file_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Extracts Rust binary metadata: compiler version, crate dependencies
    (name, version, features), toolchain, and dependencies imphash.

    Args:
        file_path: Optional path to a Rust binary. If None, uses the loaded file.
    """
    await ctx.info("Analysing Rust binary")
    _check_lib("rustbininfo", RUSTBININFO_AVAILABLE, "rust_analyze")
    target = _get_filepath(file_path)

    def _parse():
        try:
            info = rustbininfo.get_info(target) if hasattr(rustbininfo, 'get_info') else None
        except Exception:
            info = None

        result: Dict[str, Any] = {"file": target}

        # Try various API shapes since rustbininfo evolves
        if info:
            result["is_rust_binary"] = True
            if hasattr(info, 'compiler_version'):
                result["compiler_version"] = str(info.compiler_version)
            if hasattr(info, 'rustc_commit_hash'):
                result["rustc_commit_hash"] = str(info.rustc_commit_hash)
            if hasattr(info, 'toolchain'):
                result["toolchain"] = str(info.toolchain)
            if hasattr(info, 'dependencies'):
                deps = []
                for dep in info.dependencies:
                    deps.append({
                        "name": dep.name if hasattr(dep, 'name') else str(dep),
                        "version": str(dep.version) if hasattr(dep, 'version') else None,
                    })
                result["dependencies"] = deps
                result["dependency_count"] = len(deps)
            if hasattr(info, 'deps_imphash'):
                result["dependencies_imphash"] = str(info.deps_imphash)
        else:
            # Fallback: try the RustBinaryInfo class
            try:
                rbi = rustbininfo.RustBinaryInfo(target) if hasattr(rustbininfo, 'RustBinaryInfo') else None
                if rbi:
                    result["is_rust_binary"] = True
                    result["compiler_version"] = str(rbi.compiler_version) if hasattr(rbi, 'compiler_version') else None
                    result["dependencies"] = [str(d) for d in rbi.dependencies] if hasattr(rbi, 'dependencies') else []
                else:
                    result["is_rust_binary"] = False
                    result["note"] = "Could not detect Rust metadata in this binary."
            except Exception as e:
                result["is_rust_binary"] = False
                result["error"] = f"Rust analysis failed: {e}"

        return result

    result = await asyncio.to_thread(_parse)
    return await _check_mcp_response_size(ctx, result, "rust_analyze")


@tool_decorator
async def rust_demangle_symbols(
    ctx: Context,
    symbols: List[str],
    limit: int = 200,
) -> Dict[str, Any]:
    """
    Demangles Rust symbol names to human-readable form.
    e.g. '_ZN3foo3bar17h05af221e174051e8E' -> 'foo::bar'

    Args:
        symbols: List of mangled Rust symbol names.
        limit: Max symbols to return.
    """
    await ctx.info(f"Demangling {len(symbols)} Rust symbols")
    _check_lib("rust_demangler", RUST_DEMANGLER_AVAILABLE, "rust_demangle_symbols", "rust-demangler")

    def _demangle():
        results = []
        for sym in symbols[:limit]:
            try:
                demangled = rust_demangler.demangle(sym)
                results.append({"mangled": sym, "demangled": demangled})
            except Exception:
                results.append({"mangled": sym, "demangled": sym, "note": "could not demangle"})
        return results

    demangled = await asyncio.to_thread(_demangle)
    return {
        "total": len(demangled),
        "symbols": demangled,
    }


# ===================================================================
#  ELF ANALYSIS — pyelftools
# ===================================================================

@tool_decorator
async def elf_analyze(
    ctx: Context,
    file_path: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Comprehensive ELF binary analysis: file header, program headers, sections,
    symbols, dynamic dependencies, and notes.

    Args:
        file_path: Optional path to an ELF binary. If None, uses the loaded file.
        limit: Max entries per category.
    """
    await ctx.info("Analysing ELF binary")
    _check_lib("pyelftools", PYELFTOOLS_AVAILABLE, "elf_analyze", "pyelftools")
    target = _get_filepath(file_path)

    def _parse():
        try:
            with open(target, 'rb') as f:
                elf = ELFFile(f)

                result: Dict[str, Any] = {"file": target, "is_elf": True}

                # File header
                result["header"] = {
                    "class": elf.elfclass,
                    "data_encoding": elf.little_endian and "little-endian" or "big-endian",
                    "os_abi": elf['e_ident']['EI_OSABI'],
                    "type": elf['e_type'],
                    "machine": elf['e_machine'],
                    "entry_point": hex(elf['e_entry']),
                    "program_header_count": elf['e_phnum'],
                    "section_header_count": elf['e_shnum'],
                }

                # Sections
                sections = []
                for sec in elf.iter_sections():
                    sections.append({
                        "name": sec.name,
                        "type": sec['sh_type'],
                        "address": hex(sec['sh_addr']),
                        "offset": hex(sec['sh_offset']),
                        "size": sec['sh_size'],
                        "flags": sec['sh_flags'],
                    })
                    if len(sections) >= limit:
                        break
                result["sections"] = sections

                # Program headers (segments)
                segments = []
                for seg in elf.iter_segments():
                    segments.append({
                        "type": seg['p_type'],
                        "offset": hex(seg['p_offset']),
                        "virtual_address": hex(seg['p_vaddr']),
                        "physical_address": hex(seg['p_paddr']),
                        "file_size": seg['p_filesz'],
                        "memory_size": seg['p_memsz'],
                        "flags": seg['p_flags'],
                    })
                result["segments"] = segments

                # Symbols
                symbols = []
                for sec in elf.iter_sections():
                    if isinstance(sec, SymbolTableSection):
                        for sym in sec.iter_symbols():
                            if sym.name:
                                symbols.append({
                                    "name": sym.name,
                                    "value": hex(sym['st_value']),
                                    "size": sym['st_size'],
                                    "type": sym['st_info']['type'],
                                    "bind": sym['st_info']['bind'],
                                    "section_index": sym['st_shndx'],
                                })
                                if len(symbols) >= limit:
                                    break
                    if len(symbols) >= limit:
                        break
                result["symbols"] = symbols

                # Dynamic section (shared library dependencies)
                dynamic_deps = []
                for sec in elf.iter_sections():
                    if sec['sh_type'] == 'SHT_DYNAMIC':
                        for tag in sec.iter_tags():
                            if tag['d_tag'] == 'DT_NEEDED':
                                dynamic_deps.append(tag.needed)
                result["dynamic_dependencies"] = dynamic_deps

                # Notes
                notes = []
                for sec in elf.iter_sections():
                    if sec['sh_type'] == 'SHT_NOTE':
                        try:
                            for note in sec.iter_notes():
                                notes.append({
                                    "name": note['n_name'],
                                    "type": note['n_type'],
                                    "desc_size": len(note['n_desc']) if isinstance(note['n_desc'], (bytes, str)) else None,
                                })
                                if len(notes) >= limit:
                                    break
                        except Exception:
                            pass
                result["notes"] = notes

                result["summary"] = {
                    "sections": len(sections),
                    "symbols": len(symbols),
                    "dynamic_dependencies": len(dynamic_deps),
                    "segments": len(segments),
                }

                return result

        except Exception as e:
            return {"error": f"Not a valid ELF binary or parsing failed: {e}"}

    result = await asyncio.to_thread(_parse)
    return await _check_mcp_response_size(ctx, result, "elf_analyze", "the 'limit' parameter")


@tool_decorator
async def elf_dwarf_info(
    ctx: Context,
    file_path: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Extracts DWARF debug information from an ELF binary: compilation units,
    function names, source files, and line number mappings.

    Args:
        file_path: Optional path to an ELF binary. If None, uses the loaded file.
        limit: Max entries per category.
    """
    await ctx.info("Extracting DWARF debug info")
    _check_lib("pyelftools", PYELFTOOLS_AVAILABLE, "elf_dwarf_info", "pyelftools")
    target = _get_filepath(file_path)

    def _parse():
        try:
            with open(target, 'rb') as f:
                elf = ELFFile(f)

                if not elf.has_dwarf_info():
                    return {"note": "No DWARF debug info found in this binary."}

                dwarf = elf.get_dwarf_info()
                result: Dict[str, Any] = {"file": target, "has_dwarf": True}

                # Compilation units
                comp_units = []
                functions = []
                for cu in dwarf.iter_CUs():
                    top_die = cu.get_top_DIE()
                    cu_info = {
                        "offset": cu.cu_offset,
                        "name": top_die.attributes.get('DW_AT_name', {}).value.decode('utf-8', 'ignore') if 'DW_AT_name' in top_die.attributes else None,
                        "comp_dir": top_die.attributes.get('DW_AT_comp_dir', {}).value.decode('utf-8', 'ignore') if 'DW_AT_comp_dir' in top_die.attributes else None,
                        "language": top_die.attributes.get('DW_AT_language', {}).value if 'DW_AT_language' in top_die.attributes else None,
                    }
                    comp_units.append(cu_info)

                    # Extract function DIEs
                    for die in cu.iter_DIEs():
                        if die.tag == 'DW_TAG_subprogram':
                            name = None
                            if 'DW_AT_name' in die.attributes:
                                name = die.attributes['DW_AT_name'].value
                                if isinstance(name, bytes):
                                    name = name.decode('utf-8', 'ignore')
                            low_pc = die.attributes.get('DW_AT_low_pc', {})
                            addr = low_pc.value if hasattr(low_pc, 'value') else None
                            if name:
                                functions.append({
                                    "name": name,
                                    "address": hex(addr) if isinstance(addr, int) else None,
                                })
                                if len(functions) >= limit:
                                    break

                    if len(comp_units) >= limit:
                        break

                result["compilation_units"] = comp_units
                result["functions"] = functions
                result["summary"] = {
                    "compilation_units": len(comp_units),
                    "functions_with_names": len(functions),
                }
                return result

        except Exception as e:
            return {"error": f"DWARF parsing failed: {e}"}

    result = await asyncio.to_thread(_parse)
    return await _check_mcp_response_size(ctx, result, "elf_dwarf_info", "the 'limit' parameter")


# ===================================================================
#  MACH-O ANALYSIS — LIEF
# ===================================================================

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


# ===================================================================
#  AUTO-FORMAT DETECTION
# ===================================================================

@tool_decorator
async def detect_binary_format(
    ctx: Context,
    file_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Auto-detects binary format from magic bytes: PE, ELF, Mach-O, .NET, Go, Rust.
    Returns the format, suggested analysis tools, and basic metadata.

    Args:
        file_path: Optional path to a binary. If None, uses the loaded file.
    """
    await ctx.info("Detecting binary format")
    target = _get_filepath(file_path)

    def _detect():
        with open(target, 'rb') as f:
            header = f.read(4096)
            file_size = f.seek(0, 2)
            f.seek(0)

        result: Dict[str, Any] = {"file": target, "size": file_size}
        formats = []
        suggested_tools = []

        # ELF
        if header[:4] == b'\x7fELF':
            formats.append("ELF")
            bits = "64-bit" if header[4] == 2 else "32-bit"
            endian = "little-endian" if header[5] == 1 else "big-endian"
            result["elf_info"] = {"bits": bits, "endianness": endian}
            suggested_tools.extend(["elf_analyze", "elf_dwarf_info"])

        # Mach-O
        elif header[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                            b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
            formats.append("Mach-O")
            is_64 = header[:4] in (b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe')
            result["macho_info"] = {"bits": "64-bit" if is_64 else "32-bit"}
            suggested_tools.extend(["macho_analyze"])

        # Mach-O Fat/Universal
        elif header[:4] in (b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
            formats.append("Mach-O Fat/Universal")
            suggested_tools.extend(["macho_analyze"])

        # PE
        elif header[:2] == b'MZ':
            formats.append("PE")
            suggested_tools.extend(["open_file", "get_triage_report"])

            # Check for .NET
            try:
                pe_offset = struct.unpack_from('<I', header, 0x3C)[0]
                if pe_offset + 4 < len(header) and header[pe_offset:pe_offset+4] == b'PE\x00\x00':
                    # Check for COM descriptor (data directory index 14)
                    oh_offset = pe_offset + 24
                    # Optional header magic
                    oh_magic = struct.unpack_from('<H', header, oh_offset)[0]
                    if oh_magic == 0x10b:  # PE32
                        com_desc_rva_offset = oh_offset + 208  # 14th data dir
                    elif oh_magic == 0x20b:  # PE32+
                        com_desc_rva_offset = oh_offset + 224
                    else:
                        com_desc_rva_offset = None

                    if com_desc_rva_offset and com_desc_rva_offset + 8 <= len(header):
                        com_rva = struct.unpack_from('<I', header, com_desc_rva_offset)[0]
                        if com_rva > 0:
                            formats.append(".NET")
                            suggested_tools.extend(["dotnet_analyze", "dotnet_disassemble_method"])
            except Exception:
                pass

        else:
            formats.append("Unknown")

        # Check for Go signatures (in any format)
        if b'Go build' in header or b'go.buildid' in header or b'runtime.main' in header:
            formats.append("Go")
            suggested_tools.extend(["go_analyze"])

        # Check for Rust signatures
        if b'rustc/' in header or b'.rustc' in header or b'rust_begin_unwind' in header:
            formats.append("Rust")
            suggested_tools.extend(["rust_analyze", "rust_demangle_symbols"])

        result["detected_formats"] = formats
        result["primary_format"] = formats[0] if formats else "Unknown"
        result["suggested_tools"] = list(dict.fromkeys(suggested_tools))  # dedupe preserving order

        # Report available libraries
        result["library_support"] = {
            "dnfile": DNFILE_AVAILABLE,
            "dncil": DNCIL_AVAILABLE,
            "pygore": PYGORE_AVAILABLE,
            "rustbininfo": RUSTBININFO_AVAILABLE,
            "rust_demangler": RUST_DEMANGLER_AVAILABLE,
            "pyelftools": PYELFTOOLS_AVAILABLE,
            "lief": LIEF_AVAILABLE,
        }

        return result

    result = await asyncio.to_thread(_detect)
    return await _check_mcp_response_size(ctx, result, "detect_binary_format")
