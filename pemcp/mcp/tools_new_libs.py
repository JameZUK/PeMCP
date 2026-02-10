"""MCP tools powered by new library integrations — LIEF, Capstone, Keystone, Speakeasy, etc."""
import asyncio
import os
import struct
import math
import json

from typing import Dict, Any, Optional, List

from pemcp.config import state, logger, Context
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_angr_ready, _check_mcp_response_size

# ---------------------------------------------------------------------------
#  Optional library availability flags
# ---------------------------------------------------------------------------

LIEF_AVAILABLE = False
try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    pass

CAPSTONE_AVAILABLE = False
try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    pass

KEYSTONE_AVAILABLE = False
try:
    import keystone
    KEYSTONE_AVAILABLE = True
except ImportError:
    pass

SPEAKEASY_AVAILABLE = False
try:
    import speakeasy
    SPEAKEASY_AVAILABLE = True
except ImportError:
    pass

UNIPACKER_AVAILABLE = False
try:
    from unipacker.core import UnpackerClient
    UNIPACKER_AVAILABLE = True
except ImportError:
    pass

DOTNETFILE_AVAILABLE = False
try:
    import dotnetfile
    DOTNETFILE_AVAILABLE = True
except ImportError:
    pass

PPDEEP_AVAILABLE = False
try:
    import ppdeep
    PPDEEP_AVAILABLE = True
except ImportError:
    pass

TLSH_AVAILABLE = False
try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    pass

BINWALK_AVAILABLE = False
try:
    import binwalk
    BINWALK_AVAILABLE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def _check_lib(lib_name: str, available: bool, tool_name: str):
    if not available:
        raise RuntimeError(
            f"[{tool_name}] The '{lib_name}' library is not installed. "
            f"Install with: pip install {lib_name}"
        )


# ===================================================================
#  LIEF — Binary modification and multi-format parsing
# ===================================================================

@tool_decorator
async def parse_binary_with_lief(ctx: Context, file_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Parses a PE/ELF/Mach-O binary using LIEF for cross-format analysis.
    Returns headers, sections, imports, exports, and format-specific metadata.
    Falls back to the currently loaded file if no path is given.

    Args:
        file_path: Optional path to any binary. If None, uses the loaded file.
    """
    await ctx.info("Parsing binary with LIEF")
    _check_lib("lief", LIEF_AVAILABLE, "parse_binary_with_lief")

    target = file_path or state.filepath
    if not target or not os.path.isfile(target):
        raise RuntimeError("No file specified and no file is loaded.")

    def _parse():
        binary = lief.parse(target)
        if binary is None:
            return {"error": f"LIEF could not parse {target}"}

        result = {
            "format": str(binary.format).split(".")[-1],
            "name": binary.name,
            "entrypoint": hex(binary.entrypoint) if binary.entrypoint else None,
        }

        # Sections
        sections = []
        for sec in binary.sections:
            sections.append({
                "name": sec.name,
                "size": sec.size,
                "virtual_size": sec.virtual_size if hasattr(sec, 'virtual_size') else None,
                "entropy": round(sec.entropy, 4),
            })
        result["sections"] = sections

        # Imports
        if hasattr(binary, 'imports') and binary.imports:
            imports = []
            for imp in list(binary.imports)[:200]:
                imports.append(str(imp.name) if hasattr(imp, 'name') else str(imp))
            result["imports_count"] = len(binary.imports)
            result["imports_sample"] = imports[:100]

        # PE-specific
        if binary.format == lief.Binary.FORMATS.PE:
            pe = binary
            result["pe_info"] = {
                "machine": str(pe.header.machine).split(".")[-1] if hasattr(pe.header, 'machine') else None,
                "has_debug": pe.has_debug if hasattr(pe, 'has_debug') else None,
                "has_tls": pe.has_tls if hasattr(pe, 'has_tls') else None,
                "has_resources": pe.has_resources if hasattr(pe, 'has_resources') else None,
                "has_signatures": pe.has_signatures if hasattr(pe, 'has_signatures') else None,
                "is_pie": pe.is_pie if hasattr(pe, 'is_pie') else None,
            }
            # Debug info
            if hasattr(pe, 'debug') and pe.debug:
                debug_entries = []
                for d in pe.debug:
                    if hasattr(d, 'codeview') and d.codeview:
                        cv = d.codeview
                        debug_entries.append({
                            "pdb_path": cv.filename if hasattr(cv, 'filename') else None,
                            "guid": str(cv.guid) if hasattr(cv, 'guid') else None,
                        })
                result["debug_info"] = debug_entries

        # ELF-specific
        elif binary.format == lief.Binary.FORMATS.ELF:
            elf = binary
            result["elf_info"] = {
                "type": str(elf.header.file_type).split(".")[-1] if hasattr(elf.header, 'file_type') else None,
                "machine": str(elf.header.machine_type).split(".")[-1] if hasattr(elf.header, 'machine_type') else None,
                "has_interpreter": bool(elf.interpreter) if hasattr(elf, 'interpreter') else None,
                "interpreter": elf.interpreter if hasattr(elf, 'interpreter') else None,
            }

        return result

    result = await asyncio.to_thread(_parse)
    return await _check_mcp_response_size(ctx, result, "parse_binary_with_lief")


@tool_decorator
async def modify_pe_section(
    ctx: Context,
    section_name: str,
    new_name: Optional[str] = None,
    add_characteristics: Optional[int] = None,
    remove_characteristics: Optional[int] = None,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Modifies a PE section's properties (name, characteristics) using LIEF.

    Args:
        section_name: Name of the section to modify (e.g. '.text').
        new_name: New name for the section.
        add_characteristics: Characteristics flags to add (bitwise OR).
        remove_characteristics: Characteristics flags to remove.
        output_path: If provided, saves modified binary to this path.
    """
    await ctx.info(f"Modifying section {section_name}")
    _check_lib("lief", LIEF_AVAILABLE, "modify_pe_section")
    _check_pe_loaded("modify_pe_section")

    def _modify():
        binary = lief.parse(state.filepath)
        if binary is None:
            return {"error": "LIEF could not parse the loaded file."}

        section = None
        for sec in binary.sections:
            if sec.name.strip('\x00') == section_name.strip('\x00'):
                section = sec
                break

        if section is None:
            return {"error": f"Section '{section_name}' not found."}

        changes = []
        if new_name:
            section.name = new_name
            changes.append(f"Renamed to '{new_name}'")
        if add_characteristics:
            section.characteristics = section.characteristics | add_characteristics
            changes.append(f"Added characteristics {hex(add_characteristics)}")
        if remove_characteristics:
            section.characteristics = section.characteristics & ~remove_characteristics
            changes.append(f"Removed characteristics {hex(remove_characteristics)}")

        if output_path:
            builder = lief.PE.Builder(binary)
            builder.build()
            builder.write(output_path)
            changes.append(f"Saved to {output_path}")

        return {"status": "success", "changes": changes}

    result = await asyncio.to_thread(_modify)
    return await _check_mcp_response_size(ctx, result, "modify_pe_section")


# ===================================================================
#  CAPSTONE — Standalone disassembly
# ===================================================================

@tool_decorator
async def disassemble_raw_bytes(
    ctx: Context,
    hex_bytes: str,
    architecture: str = "x86_64",
    base_address: str = "0x0",
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Disassembles raw bytes (shellcode, buffer contents) without needing a loaded binary.
    Supports x86, x86_64, ARM, ARM64, MIPS.

    Args:
        hex_bytes: Hex-encoded bytes to disassemble (e.g. '554889e5...').
        architecture: Target architecture ('x86', 'x86_64', 'arm', 'arm64', 'mips').
        base_address: Base address for display (default '0x0').
        limit: Max instructions to return.
    """
    await ctx.info(f"Disassembling raw bytes ({architecture})")
    _check_lib("capstone", CAPSTONE_AVAILABLE, "disassemble_raw_bytes")

    try:
        code = bytes.fromhex(hex_bytes)
    except ValueError:
        raise ValueError("Invalid hex bytes.")

    base_addr = int(base_address, 16)

    ARCH_MAP = {
        "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        "x86_64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
        "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        "mips": (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32),
    }

    if architecture not in ARCH_MAP:
        raise ValueError(f"Unsupported architecture. Supported: {', '.join(ARCH_MAP.keys())}")

    arch, mode = ARCH_MAP[architecture]

    def _disasm():
        md = capstone.Cs(arch, mode)
        md.detail = True
        instructions = []
        for insn in md.disasm(code, base_addr):
            entry = {
                "address": hex(insn.address),
                "bytes": insn.bytes.hex(),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
            }
            # Add implicit register info
            if insn.regs_read:
                entry["regs_read"] = [insn.reg_name(r) for r in insn.regs_read]
            if insn.regs_write:
                entry["regs_write"] = [insn.reg_name(r) for r in insn.regs_write]
            if insn.groups:
                entry["groups"] = [insn.group_name(g) for g in insn.groups]

            instructions.append(entry)
            if len(instructions) >= limit:
                break

        return instructions

    instructions = await asyncio.to_thread(_disasm)

    return {
        "architecture": architecture,
        "base_address": hex(base_addr),
        "total_bytes": len(code),
        "instruction_count": len(instructions),
        "instructions": instructions,
    }


# ===================================================================
#  KEYSTONE — Assembler
# ===================================================================

@tool_decorator
async def assemble_instruction(
    ctx: Context,
    assembly: str,
    architecture: str = "x86_64",
    base_address: str = "0x0",
) -> Dict[str, Any]:
    """
    Converts assembly mnemonics to machine code bytes.
    Useful for creating patches in human-readable form.

    Args:
        assembly: Assembly code string (e.g. 'nop; mov eax, 1; ret').
        architecture: Target architecture ('x86', 'x86_64', 'arm', 'arm64', 'mips').
        base_address: Base address for resolving relative references.
    """
    await ctx.info(f"Assembling: {assembly[:60]}")
    _check_lib("keystone", KEYSTONE_AVAILABLE, "assemble_instruction")

    base_addr = int(base_address, 16)

    ARCH_MAP = {
        "x86": (keystone.KS_ARCH_X86, keystone.KS_MODE_32),
        "x86_64": (keystone.KS_ARCH_X86, keystone.KS_MODE_64),
        "arm": (keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM),
        "arm64": (keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN),
        "mips": (keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32),
    }

    if architecture not in ARCH_MAP:
        raise ValueError(f"Unsupported architecture. Supported: {', '.join(ARCH_MAP.keys())}")

    arch, mode = ARCH_MAP[architecture]

    def _assemble():
        ks = keystone.Ks(arch, mode)
        try:
            encoding, count = ks.asm(assembly, base_addr)
            if encoding is None:
                return {"error": "Assembly failed: no output produced."}
            machine_code = bytes(encoding)
            return {
                "machine_code_hex": machine_code.hex(),
                "byte_count": len(machine_code),
                "instruction_count": count,
                "assembly_input": assembly,
            }
        except keystone.KsError as e:
            return {"error": f"Assembly failed: {e}"}

    result = await asyncio.to_thread(_assemble)
    return await _check_mcp_response_size(ctx, result, "assemble_instruction")


@tool_decorator
async def patch_with_assembly(
    ctx: Context,
    address: str,
    assembly: str,
    architecture: str = "x86_64",
) -> Dict[str, Any]:
    """
    Assembles instructions and patches them into the loaded binary at the given address.
    Combines Keystone (assembly) with angr (memory patching).

    Args:
        address: Hex address to patch at.
        assembly: Assembly mnemonics to assemble and write.
        architecture: Target architecture.
    """
    await ctx.info(f"Assembling and patching at {address}")
    _check_lib("keystone", KEYSTONE_AVAILABLE, "patch_with_assembly")
    _check_angr_ready("patch_with_assembly")

    from pemcp.config import ANGR_AVAILABLE
    import angr

    addr = int(address, 16)

    ARCH_MAP = {
        "x86": (keystone.KS_ARCH_X86, keystone.KS_MODE_32),
        "x86_64": (keystone.KS_ARCH_X86, keystone.KS_MODE_64),
    }

    if architecture not in ARCH_MAP:
        raise ValueError(f"Unsupported architecture for patching: {', '.join(ARCH_MAP.keys())}")

    arch, mode = ARCH_MAP[architecture]

    def _patch():
        ks = keystone.Ks(arch, mode)
        try:
            encoding, count = ks.asm(assembly, addr)
        except keystone.KsError as e:
            return {"error": f"Assembly failed: {e}"}

        if encoding is None:
            return {"error": "Assembly produced no output."}

        patch_data = bytes(encoding)

        if state.angr_project is None:
            state.angr_project = angr.Project(state.filepath, auto_load_libs=False)

        state.angr_project.loader.memory.store(addr, patch_data)
        state.angr_cfg = None  # Invalidate CFG
        state.angr_loop_cache = None

        return {
            "status": "success",
            "address": hex(addr),
            "assembly": assembly,
            "bytes_written": len(patch_data),
            "machine_code_hex": patch_data.hex(),
            "message": f"Patched {len(patch_data)} bytes. CFG cache cleared.",
        }

    result = await asyncio.to_thread(_patch)
    return await _check_mcp_response_size(ctx, result, "patch_with_assembly")


# ===================================================================
#  SIMILARITY HASHING — ssdeep, TLSH
# ===================================================================

@tool_decorator
async def compute_similarity_hashes(ctx: Context, file_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Computes fuzzy/locality-sensitive hashes for sample similarity analysis:
    ssdeep (context-triggered piecewise hash) and TLSH (Trend Micro Locality Sensitive Hash).

    Args:
        file_path: Optional path to a file. If None, uses the loaded file.
    """
    await ctx.info("Computing similarity hashes")
    target = file_path or state.filepath
    if not target or not os.path.isfile(target):
        raise RuntimeError("No file specified and no file is loaded.")

    def _compute():
        with open(target, 'rb') as f:
            data = f.read()

        result = {"file": target, "size": len(data)}

        if PPDEEP_AVAILABLE:
            try:
                result["ssdeep"] = ppdeep.hash(data)
            except Exception as e:
                result["ssdeep_error"] = str(e)
        else:
            result["ssdeep"] = "ppdeep not installed (pip install ppdeep)"

        if TLSH_AVAILABLE:
            try:
                h = tlsh.hash(data)
                result["tlsh"] = h if h else "data too small for TLSH"
            except Exception as e:
                result["tlsh_error"] = str(e)
        else:
            result["tlsh"] = "tlsh not installed (pip install py-tlsh)"

        # Standard imphash if PE is loaded
        if state.pe_object:
            try:
                result["imphash"] = state.pe_object.get_imphash()
            except Exception:
                pass

        return result

    result = await asyncio.to_thread(_compute)
    return await _check_mcp_response_size(ctx, result, "compute_similarity_hashes")


@tool_decorator
async def compare_file_similarity(
    ctx: Context,
    file_path_b: str,
) -> Dict[str, Any]:
    """
    Compares the loaded file against another file using fuzzy hashes
    to determine similarity (useful for malware family clustering).

    Args:
        file_path_b: Path to the second file to compare.
    """
    await ctx.info(f"Comparing similarity with {file_path_b}")
    if not state.filepath or not os.path.isfile(state.filepath):
        raise RuntimeError("No file is loaded.")
    if not os.path.isfile(file_path_b):
        raise RuntimeError(f"File not found: {file_path_b}")

    def _compare():
        with open(state.filepath, 'rb') as f:
            data_a = f.read()
        with open(file_path_b, 'rb') as f:
            data_b = f.read()

        result = {"file_a": state.filepath, "file_b": file_path_b}

        if PPDEEP_AVAILABLE:
            try:
                hash_a = ppdeep.hash(data_a)
                hash_b = ppdeep.hash(data_b)
                score = ppdeep.compare(hash_a, hash_b)
                result["ssdeep_similarity"] = score
                result["ssdeep_hash_a"] = hash_a
                result["ssdeep_hash_b"] = hash_b
            except Exception as e:
                result["ssdeep_error"] = str(e)

        if TLSH_AVAILABLE:
            try:
                h_a = tlsh.hash(data_a)
                h_b = tlsh.hash(data_b)
                if h_a and h_b:
                    distance = tlsh.diff(h_a, h_b)
                    result["tlsh_distance"] = distance
                    result["tlsh_hash_a"] = h_a
                    result["tlsh_hash_b"] = h_b
                    result["tlsh_verdict"] = "very similar" if distance < 30 else "similar" if distance < 100 else "different"
            except Exception as e:
                result["tlsh_error"] = str(e)

        return result

    result = await asyncio.to_thread(_compare)
    return await _check_mcp_response_size(ctx, result, "compare_file_similarity")


# ===================================================================
#  SPEAKEASY — Windows API emulation
# ===================================================================

@tool_decorator
async def emulate_pe_with_windows_apis(
    ctx: Context,
    timeout_seconds: int = 60,
    limit: int = 200,
) -> Dict[str, Any]:
    """
    Emulates the loaded PE in Speakeasy's Windows environment with full API emulation.
    Returns the API call log (DLL function calls, arguments, return values).

    Args:
        timeout_seconds: Max emulation time in seconds.
        limit: Max API calls to return.
    """
    await ctx.info("Emulating PE with Speakeasy Windows API emulation")
    _check_lib("speakeasy", SPEAKEASY_AVAILABLE, "emulate_pe_with_windows_apis")
    _check_pe_loaded("emulate_pe_with_windows_apis")

    def _emulate():
        se = speakeasy.Speakeasy()
        try:
            module = se.load_module(state.filepath)
        except Exception as e:
            return {"error": f"Failed to load module: {e}"}

        try:
            se.run_module(module, timeout=timeout_seconds)
        except Exception as e:
            # Emulation may raise on exit or unhandled API
            pass

        # Collect API call log
        api_calls = []
        for event in se.get_report().get('api_calls', []):
            api_calls.append({
                "api": event.get('api_name', ''),
                "args": event.get('args', [])[:5],
                "ret_val": event.get('ret_val'),
                "caller": hex(event['caller']) if event.get('caller') else None,
            })
            if len(api_calls) >= limit:
                break

        report = se.get_report()

        return {
            "status": "completed",
            "total_api_calls": len(report.get('api_calls', [])),
            "api_calls": api_calls,
            "strings_found": report.get('strings', [])[:100],
            "network_activity": report.get('network', [])[:50],
            "file_activity": report.get('file_access', [])[:50],
            "registry_activity": report.get('registry', [])[:50],
        }

    result = await asyncio.to_thread(_emulate)
    return await _check_mcp_response_size(ctx, result, "emulate_pe_with_windows_apis", "the 'limit' parameter")


@tool_decorator
async def emulate_shellcode_with_speakeasy(
    ctx: Context,
    shellcode_hex: Optional[str] = None,
    architecture: str = "x86",
    timeout_seconds: int = 30,
    limit: int = 200,
) -> Dict[str, Any]:
    """
    Emulates shellcode with full Windows API emulation via Speakeasy.
    If no shellcode_hex is provided, uses the loaded file as raw shellcode.

    Args:
        shellcode_hex: Hex-encoded shellcode bytes. If None, uses loaded file data.
        architecture: 'x86' or 'x86_64'.
        timeout_seconds: Max emulation time.
        limit: Max API calls to return.
    """
    await ctx.info("Emulating shellcode with Speakeasy")
    _check_lib("speakeasy", SPEAKEASY_AVAILABLE, "emulate_shellcode_with_speakeasy")

    def _emulate():
        se = speakeasy.Speakeasy()

        if shellcode_hex:
            sc_data = bytes.fromhex(shellcode_hex)
        elif state.filepath:
            with open(state.filepath, 'rb') as f:
                sc_data = f.read()
        else:
            return {"error": "No shellcode provided and no file loaded."}

        arch_val = speakeasy.ARCH_X86 if architecture == "x86" else speakeasy.ARCH_AMD64

        try:
            addr = se.load_shellcode(state.filepath if not shellcode_hex else None, sc_data, arch_val)
            se.run_shellcode(addr, timeout=timeout_seconds)
        except Exception as e:
            logger.debug(f"Speakeasy emulation ended with exception (may be expected): {e}")

        api_calls = []
        report = se.get_report()
        for event in report.get('api_calls', []):
            api_calls.append({
                "api": event.get('api_name', ''),
                "args": event.get('args', [])[:5],
                "ret_val": event.get('ret_val'),
            })
            if len(api_calls) >= limit:
                break

        return {
            "status": "completed",
            "architecture": architecture,
            "total_api_calls": len(report.get('api_calls', [])),
            "api_calls": api_calls,
            "strings_found": report.get('strings', [])[:100],
            "network_activity": report.get('network', [])[:50],
        }

    result = await asyncio.to_thread(_emulate)
    return await _check_mcp_response_size(ctx, result, "emulate_shellcode_with_speakeasy", "the 'limit' parameter")


# ===================================================================
#  UN{I}PACKER — Automatic PE unpacking
# ===================================================================

@tool_decorator
async def auto_unpack_pe(
    ctx: Context,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Automatically unpacks a packed PE using Un{i}packer (Unicorn-based).
    Supports UPX, ASPack, PEtite, FSG, and generic packing via section-hopping heuristics.

    Args:
        output_path: Where to save the unpacked binary. Default: <original>_unpacked.exe.
    """
    await ctx.info("Auto-unpacking PE")
    _check_lib("unipacker", UNIPACKER_AVAILABLE, "auto_unpack_pe")
    _check_pe_loaded("auto_unpack_pe")

    if not output_path:
        base, ext = os.path.splitext(state.filepath)
        output_path = f"{base}_unpacked{ext}"

    def _unpack():
        try:
            client = UnpackerClient(state.filepath)
            client.unpack(output_path)
            return {
                "status": "success",
                "input_file": state.filepath,
                "output_file": output_path,
                "output_size": os.path.getsize(output_path) if os.path.exists(output_path) else 0,
                "hint": "Use open_file() to load the unpacked binary for further analysis.",
            }
        except Exception as e:
            return {"error": f"Unpacking failed: {e}"}

    result = await asyncio.to_thread(_unpack)
    return await _check_mcp_response_size(ctx, result, "auto_unpack_pe")


# ===================================================================
#  DOTNETFILE — .NET metadata parsing
# ===================================================================

@tool_decorator
async def parse_dotnet_metadata(ctx: Context, limit: int = 100) -> Dict[str, Any]:
    """
    Parses .NET metadata from the loaded PE: CLR header, streams, type definitions,
    method definitions, assembly references, and user strings.

    Args:
        limit: Max entries per category.
    """
    await ctx.info("Parsing .NET metadata")
    _check_lib("dotnetfile", DOTNETFILE_AVAILABLE, "parse_dotnet_metadata")
    _check_pe_loaded("parse_dotnet_metadata")

    def _parse():
        try:
            dn = dotnetfile.DotNetPE(state.filepath)
        except Exception as e:
            return {"error": f"Not a valid .NET binary or parsing failed: {e}"}

        result = {}

        # CLR header
        try:
            result["clr_version"] = str(dn.clr_header.RuntimeVersion) if hasattr(dn, 'clr_header') else None
        except Exception as e:
            logger.debug(f"Could not read CLR version: {e}")

        # Type definitions
        types = []
        try:
            for td in dn.metadata_table_lookup("TypeDef"):
                types.append({
                    "name": str(td.TypeName),
                    "namespace": str(td.TypeNamespace),
                })
                if len(types) >= limit:
                    break
        except Exception as e:
            logger.debug(f"Error reading .NET TypeDef table: {e}")
        result["type_definitions"] = types

        # Method definitions
        methods = []
        try:
            for md in dn.metadata_table_lookup("MethodDef"):
                methods.append({
                    "name": str(md.Name),
                    "rva": hex(md.RVA) if md.RVA else None,
                })
                if len(methods) >= limit:
                    break
        except Exception as e:
            logger.debug(f"Error reading .NET MethodDef table: {e}")
        result["method_definitions"] = methods

        # Assembly references
        refs = []
        try:
            for ref in dn.metadata_table_lookup("AssemblyRef"):
                refs.append({
                    "name": str(ref.Name),
                    "version": f"{ref.MajorVersion}.{ref.MinorVersion}" if hasattr(ref, 'MajorVersion') else None,
                })
                if len(refs) >= limit:
                    break
        except Exception as e:
            logger.debug(f"Error reading .NET AssemblyRef table: {e}")
        result["assembly_references"] = refs

        # User strings
        user_strings = []
        try:
            for s in dn.get_user_strings():
                if s and len(s) > 2:
                    user_strings.append(str(s))
                if len(user_strings) >= limit:
                    break
        except Exception as e:
            logger.debug(f"Error reading .NET user strings: {e}")
        result["user_strings"] = user_strings

        return result

    result = await asyncio.to_thread(_parse)
    return await _check_mcp_response_size(ctx, result, "parse_dotnet_metadata", "the 'limit' parameter")


# ===================================================================
#  BINWALK — Embedded file detection
# ===================================================================

@tool_decorator
async def scan_for_embedded_files(
    ctx: Context,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    Scans the binary for embedded files, archives, and file system images
    using Binwalk signature scanning.

    Args:
        limit: Max findings to return.
    """
    await ctx.info("Scanning for embedded files with Binwalk")
    _check_lib("binwalk", BINWALK_AVAILABLE, "scan_for_embedded_files")
    _check_pe_loaded("scan_for_embedded_files")

    def _scan():
        try:
            results = []
            for module in binwalk.scan(state.filepath, signature=True, quiet=True, extract=False):
                for result in module.results:
                    results.append({
                        "offset": hex(result.offset),
                        "description": result.description,
                    })
                    if len(results) >= limit:
                        break
            return {
                "total_found": len(results),
                "embedded_files": results[:limit],
            }
        except Exception as e:
            return {"error": f"Binwalk scan failed: {e}"}

    result = await asyncio.to_thread(_scan)
    return await _check_mcp_response_size(ctx, result, "scan_for_embedded_files", "the 'limit' parameter")


# ===================================================================
#  CAPABILITY REPORT — available new libraries
# ===================================================================

@tool_decorator
async def get_extended_capabilities(ctx: Context) -> Dict[str, Any]:
    """
    Reports which extended libraries are available on this server instance.
    Helps the AI understand what tools it can use.
    """
    await ctx.info("Checking extended library availability")
    return {
        "lief": {"available": LIEF_AVAILABLE, "purpose": "Binary modification, multi-format parsing (PE/ELF/Mach-O)"},
        "capstone": {"available": CAPSTONE_AVAILABLE, "purpose": "Multi-architecture disassembly"},
        "keystone": {"available": KEYSTONE_AVAILABLE, "purpose": "Multi-architecture assembly"},
        "speakeasy": {"available": SPEAKEASY_AVAILABLE, "purpose": "Windows API emulation for malware analysis"},
        "unipacker": {"available": UNIPACKER_AVAILABLE, "purpose": "Automatic PE unpacking"},
        "dotnetfile": {"available": DOTNETFILE_AVAILABLE, "purpose": ".NET PE metadata parsing"},
        "ppdeep": {"available": PPDEEP_AVAILABLE, "purpose": "ssdeep fuzzy hashing"},
        "tlsh": {"available": TLSH_AVAILABLE, "purpose": "TLSH locality-sensitive hashing"},
        "binwalk": {"available": BINWALK_AVAILABLE, "purpose": "Embedded file/firmware detection"},
    }
