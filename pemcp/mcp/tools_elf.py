"""MCP tools for ELF binary analysis using pyelftools."""
import asyncio
from typing import Dict, Any, Optional
from pemcp.config import state, logger, Context
from pemcp.mcp.server import tool_decorator, _check_mcp_response_size
from pemcp.mcp._format_helpers import _check_lib, _get_filepath

PYELFTOOLS_AVAILABLE = False
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    pass


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
