"""MCP tools for exporting and importing Arkana project archives."""
import datetime
import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
import time

from pathlib import Path
from typing import Dict, Any, List

from arkana.config import state, logger, Context
from arkana.constants import (
    MAX_PROJECT_ARCHIVE_BYTES,
    MAX_PROJECT_ARCHIVE_MEMBERS,
    MAX_PROJECT_ARCHIVE_MEMBER_BYTES,
)
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.utils import _safe_env_int

try:
    from arkana import __version__ as ARKANA_VERSION
except ImportError:
    ARKANA_VERSION = "unknown"

# Extension for project archives (import accepts both old and new extensions)
PROJECT_EXTENSION = ".arkana_project.tar.gz"

# v2 archive limits — defaults from arkana/constants.py, overridable via env.
# Defends against decompression bombs / zip bombs in user-supplied archives.
_MAX_V2_ARCHIVE_BYTES = _safe_env_int(
    "ARKANA_MAX_PROJECT_ARCHIVE_MB",
    MAX_PROJECT_ARCHIVE_BYTES // (1024 * 1024),
) * 1024 * 1024
_MAX_V2_ARCHIVE_MEMBERS = _safe_env_int(
    "ARKANA_MAX_PROJECT_ARCHIVE_MEMBERS",
    MAX_PROJECT_ARCHIVE_MEMBERS,
)
_MAX_V2_MEMBER_BYTES = _safe_env_int(
    "ARKANA_MAX_PROJECT_ARCHIVE_MEMBER_MB",
    MAX_PROJECT_ARCHIVE_MEMBER_BYTES // (1024 * 1024),
) * 1024 * 1024


# ---------------------------------------------------------------------------
#  v2 project-level export/import (multi-binary, project-aware)
# ---------------------------------------------------------------------------

EXPORT_VERSION_V2 = 2


def _export_project_v2(project, output_path: str) -> Dict[str, Any]:
    """Tar+gzip a project's directory tree as a v2 archive.

    Layout inside the tarball:
        manifest.json                       (top-level wrapper, has export_version=2)
        project/manifest.json               (the project's own manifest)
        project/binaries/...                (binary copies)
        project/artifacts/...               (artifact files / directories)
        project/overlay/{sha256}.json.gz    (per-binary overlays)
    """
    abs_output = str(Path(output_path).resolve())
    state.check_path_allowed(abs_output)

    if not output_path.endswith(PROJECT_EXTENSION):
        if output_path.endswith(".tar.gz"):
            abs_output = abs_output[:-7] + PROJECT_EXTENSION
        else:
            abs_output = abs_output + PROJECT_EXTENSION

    output_dir = os.path.dirname(abs_output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    project_root = project.root  # ~/.arkana/projects/{id}/
    if not project_root.is_dir():
        raise RuntimeError(f"Project directory missing: {project_root}")

    # Top-level wrapping manifest
    top_manifest = {
        "arkana_version": ARKANA_VERSION,
        "export_version": EXPORT_VERSION_V2,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "project_id": project.id,
        "project_name": project.name,
        "member_count": len(project.manifest.members),
        "tags": list(project.manifest.tags),
    }

    with tarfile.open(abs_output, "w:gz") as tar:
        manifest_bytes = json.dumps(top_manifest, indent=2).encode("utf-8")
        info = tarfile.TarInfo(name="manifest.json")
        info.size = len(manifest_bytes)
        tar.addfile(info, io.BytesIO(manifest_bytes))
        # Add the entire project directory under "project/"
        tar.add(str(project_root), arcname="project", recursive=True)

    archive_size = os.path.getsize(abs_output)
    return {
        "status": "success",
        "archive_path": abs_output,
        "archive_size_kb": round(archive_size / 1024, 1),
        "export_version": EXPORT_VERSION_V2,
        "project_id": project.id,
        "project_name": project.name,
        "member_count": len(project.manifest.members),
    }


def _import_project_v2(abs_path: str, top_manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Unpack a v2 archive into a new project under ~/.arkana/projects/.

    The new project gets a fresh ID (we never overwrite an existing project,
    even if the archive's project_id collides with one on disk). The original
    name is preserved if available, with a collision-suffix if needed.
    """
    from arkana.projects import (
        project_manager, Project, ProjectManifest,
        PROJECTS_DIR, _new_project_id, _validate_project_name,
    )

    archive_name = top_manifest.get("project_name") or "imported_project"
    try:
        base_name = _validate_project_name(archive_name)
    except ValueError:
        base_name = "imported_project"

    new_id = _new_project_id()
    while project_manager.get(new_id) is not None:
        new_id = _new_project_id()
    new_root = PROJECTS_DIR / new_id
    new_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Resolved root is the canonical containment anchor — every extracted
    # target path must stay strictly underneath it after .resolve().
    new_root_resolved = new_root.resolve()

    try:
        with tarfile.open(abs_path, "r:gz") as tar:
            total_bytes = 0
            member_count = 0
            for member in tar:  # iterates once, streaming — cheaper than getmembers()
                member_count += 1
                if member_count > _MAX_V2_ARCHIVE_MEMBERS:
                    raise RuntimeError(
                        f"[import_project] Archive exceeds member cap "
                        f"({_MAX_V2_ARCHIVE_MEMBERS})"
                    )
                # Reject anything that isn't a plain file or directory.
                if (member.issym() or member.islnk() or member.isblk()
                        or member.ischr() or member.isfifo() or member.isdev()):
                    raise RuntimeError(
                        f"[import_project] Archive contains unsafe entry: "
                        f"'{member.name}'"
                    )
                # Absolute paths and drive-letter paths are rejected outright.
                if (member.name.startswith("/") or member.name.startswith("\\")
                        or (len(member.name) >= 2 and member.name[1] == ":")):
                    raise RuntimeError(
                        f"[import_project] Unsafe archive member (absolute path): "
                        f"'{member.name}'"
                    )
                # Only accept members under the "project/" prefix; silently
                # skip anything else (archive may include top-level metadata).
                if not member.name.startswith("project/"):
                    continue
                relative = member.name[len("project/"):]
                if not relative:
                    continue
                # Strict containment check: resolve the target and verify it
                # is underneath new_root_resolved. This is the ONE line of
                # defence that blocks path traversal even against pathological
                # "legit-looking" names that slip past os.path.normpath.
                target = (new_root / relative).resolve()
                try:
                    target.relative_to(new_root_resolved)
                except ValueError:
                    raise RuntimeError(
                        f"[import_project] Archive member escapes project root: "
                        f"'{member.name}'"
                    )
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                # Enforce per-file and total size caps before extraction.
                size = int(member.size or 0)
                if size > _MAX_V2_MEMBER_BYTES:
                    raise RuntimeError(
                        f"[import_project] Archive member '{member.name}' "
                        f"exceeds per-file size cap ({_MAX_V2_MEMBER_BYTES} bytes)"
                    )
                total_bytes += size
                if total_bytes > _MAX_V2_ARCHIVE_BYTES:
                    raise RuntimeError(
                        f"[import_project] Archive exceeds total size cap "
                        f"({_MAX_V2_ARCHIVE_BYTES} bytes)"
                    )
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                with open(target, "wb") as f:
                    shutil.copyfileobj(extracted, f, length=1 << 20)
    except Exception:
        # Any failure during extraction leaves a partial tree behind —
        # clean it up so retry can succeed and disk isn't leaked.
        shutil.rmtree(new_root, ignore_errors=True)
        raise

    # Load the extracted manifest, rewrite id+name to avoid collisions, and
    # register the project with the manager.
    manifest_path = new_root / "manifest.json"
    if not manifest_path.is_file():
        shutil.rmtree(new_root, ignore_errors=True)
        raise RuntimeError("[import_project] Archive missing project/manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        proj_manifest_data = json.load(f)
    proj_manifest_data["id"] = new_id
    name = base_name
    counter = 2
    while project_manager.find_by_name(name):
        name = f"{base_name}_{counter}"
        counter += 1
    proj_manifest_data["name"] = name
    proj_manifest_data["created_at"] = time.time()
    proj_manifest_data["last_opened"] = time.time()
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(proj_manifest_data, f, indent=2)

    project = Project(ProjectManifest.from_dict(proj_manifest_data), new_root)
    with project_manager._lock:
        project_manager._projects[new_id] = project
        project_manager._save_index()

    return {
        "status": "success",
        "import_version": EXPORT_VERSION_V2,
        "project_id": new_id,
        "project_name": name,
        "member_count": len(project.manifest.members),
        "hint": (
            f"Project imported as '{name}'. Call open_project('{name}') to load it."
        ),
    }


@tool_decorator
async def export_project(
    ctx: Context,
    output_path: str,
    include_binary: bool = True,  # noqa: ARG001 — kept for API stability; v2 always bundles project binaries
) -> Dict[str, Any]:
    """
    [Phase: utility] Export the active project as a portable v2 archive
    (.arkana_project.tar.gz). Bundles every binary in the project together
    with overlays, artifacts, notes and renames.

    ---compact: export active project as v2 .tar.gz | bundles binaries/overlays/notes | needs: project

    When to use: When sharing analysis with others or preserving a checkpoint.
    The archive can be re-imported with import_project().

    Args:
        ctx: The MCP Context object.
        output_path: (str) Path for the output archive file.
        include_binary: (bool) Ignored. Kept for backwards compatibility with
            the old single-binary v1 export API. v2 archives always bundle
            every binary in the active project.

    Returns:
        A dictionary with export status, archive path, and size.
    """
    # If a binary is loaded but the active project is still a ScratchProject,
    # promote it to a real on-disk project so we have a tree to archive.
    try:
        active = state.get_active_project() if hasattr(state, "get_active_project") else None
    except Exception:
        active = None

    if active is not None and getattr(active, "is_scratch", False):
        try:
            state._maybe_promote_scratch()
        except Exception as e:
            raise RuntimeError(
                f"[export_project] Failed to promote scratch project: {e}"
            )
        try:
            active = state.get_active_project()
        except Exception:
            active = None

    if active is None or getattr(active, "is_scratch", False):
        # Promotion didn't fire (no binary loaded, or no scratch members).
        _check_pe_loaded("export_project")
        raise RuntimeError(
            "[export_project] No project is active. Open or create a "
            "project (open_project / create_project) before exporting."
        )

    await ctx.info(f"Creating project archive: {output_path}")
    result = _export_project_v2(active, output_path)
    archive_size_kb = result.get("archive_size_kb")
    if archive_size_kb is not None:
        await ctx.info(f"Project exported: {archive_size_kb:.1f} KB")
    return result


@tool_decorator
async def import_project(
    ctx: Context,
    project_path: str,
    load_binary: bool = True,  # noqa: ARG001 — kept for API stability; v2 archives carry their own binary
) -> Dict[str, Any]:
    """
    [Phase: load] Import a previously exported v2 project archive
    (.arkana_project.tar.gz). Restores the entire project tree, including
    binaries, overlays, artifacts, and notes.

    ---compact: import v2 project archive | restores binaries/notes/artifacts/overlays as a new project

    When to use: When resuming analysis from a shared archive or a previous
    checkpoint. The archive's project is registered under a fresh ID; call
    ``open_project(name)`` afterwards to activate it.

    Args:
        ctx: The MCP Context object.
        project_path: (str) Path to the .arkana_project.tar.gz archive (v2).
        load_binary: (bool) Ignored. Kept for backwards compatibility with the
            old single-binary v1 import API. v2 archives always contain the
            project's binaries; activate them with open_project + open_file.

    Returns:
        A dictionary with import status, project id/name, and member count.
    """
    abs_path = str(Path(project_path).resolve())
    state.check_path_allowed(abs_path)

    if not os.path.isfile(abs_path):
        raise RuntimeError(f"[import_project] Archive not found: {abs_path}")

    await ctx.info(f"Importing project archive: {abs_path}")

    # Peek the top-level manifest.json to identify the archive format. Only
    # v2 (project-level) archives are supported — v1 single-binary session
    # exports were retired with the cache → project overlay split.
    try:
        with tarfile.open(abs_path, "r:gz") as _peek:
            try:
                _mf_member = _peek.extractfile("manifest.json")
            except KeyError:
                _mf_member = None
            if _mf_member is None:
                raise RuntimeError(
                    "[import_project] Archive missing manifest.json — not a "
                    "valid Arkana project archive."
                )
            try:
                top_manifest = json.loads(_mf_member.read().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                raise RuntimeError(
                    f"[import_project] Cannot parse archive manifest.json: {e}"
                )
    except (tarfile.TarError, OSError) as e:
        raise RuntimeError(f"[import_project] Failed to read archive: {e}")

    if not isinstance(top_manifest, dict):
        raise RuntimeError("[import_project] Invalid manifest.json contents")

    export_version = top_manifest.get("export_version")
    if export_version != EXPORT_VERSION_V2:
        raise RuntimeError(
            f"[import_project] Unsupported archive format (export_version="
            f"{export_version!r}). Only v2 project archives are supported. "
            "v1 session archives were retired when user state moved out of "
            "the cache and into project overlays."
        )

    result = _import_project_v2(abs_path, top_manifest)
    name = result.get("project_name")
    if name:
        await ctx.info(f"Project '{name}' imported successfully.")
    return result


# ---------------------------------------------------------------------------
#  Ghidra / IDA script export helpers
# ---------------------------------------------------------------------------

# Maximum generated script size (10 MB — scripts are plain text)
_MAX_SCRIPT_SIZE = 10 * 1024 * 1024


def _get_file_metadata() -> Dict[str, str]:
    """Return common file metadata for script headers."""
    hashes = (state.pe_data.get("file_hashes") or {})
    sha256 = hashes.get("sha256", "unknown")
    filename = os.path.basename(state.filepath) if state.filepath else "unknown"
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return {"sha256": sha256, "filename": filename, "timestamp": timestamp}


def _resolve_output_path(output_path: str, suffix: str) -> str:
    """Resolve and validate the output path for a generated script."""
    if not output_path:
        # Auto-generate path next to the loaded binary
        base_dir = os.path.dirname(state.filepath) if state.filepath else tempfile.gettempdir()
        base_name = os.path.splitext(os.path.basename(state.filepath))[0] if state.filepath else "arkana_export"
        output_path = os.path.join(base_dir, f"{base_name}{suffix}")

    abs_path = str(Path(output_path).resolve())
    state.check_path_allowed(abs_path)

    # Create parent directory if needed
    parent = os.path.dirname(abs_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    return abs_path


def _write_script_and_register(abs_path: str, script_text: str, source_tool: str,
                                description: str) -> Dict[str, Any]:
    """Write a script to disk, compute hashes, and register as artifact."""
    data = script_text.encode("utf-8")
    if len(data) > _MAX_SCRIPT_SIZE:
        raise RuntimeError(
            f"Generated script is too large ({len(data) // 1024} KB). "
            f"Maximum is {_MAX_SCRIPT_SIZE // (1024 * 1024)} MB."
        )

    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()

    Path(abs_path).write_bytes(data)
    logger.info("Script written: %s (%d bytes)", abs_path, len(data))

    artifact = state.register_artifact(
        path=abs_path,
        sha256=sha256,
        md5=md5,
        size=len(data),
        source_tool=source_tool,
        description=description,
        detected_type="Python script",
    )
    return {"path": abs_path, "size": len(data), "sha256": sha256, "artifact_id": artifact["id"]}


def _escape_python_string(s: str) -> str:
    """Escape a string for use inside a Python repr/string literal."""
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t").replace("\x00", "\\x00")
    # Escape remaining control characters
    return "".join(c if c.isprintable() or c == " " else f"\\x{ord(c):02x}" for c in s)


def _collect_function_notes(notes: List[Dict[str, Any]]) -> Dict[str, str]:
    """Collect notes with category 'function' grouped by address.

    Returns {addr_hex: combined_comment_text}.
    """
    addr_notes: Dict[str, List[str]] = {}
    for note in notes:
        addr = note.get("address")
        if not addr:
            continue
        cat = note.get("category", "")
        content = note.get("content", "").strip()
        if not content:
            continue
        # Include function notes and any note attached to an address
        if cat in ("function", "tool_result", "ioc", "general"):
            addr_notes.setdefault(addr, []).append(f"[{cat}] {content}")
    # Combine multiple notes for the same address
    return {addr: "\n".join(texts) for addr, texts in addr_notes.items()}


def _collect_bookmarks(triage_status: Dict[str, str],
                       function_renames: Dict[str, str]) -> List[Dict[str, str]]:
    """Collect bookmark entries from triage status."""
    bookmarks = []
    for addr, status in triage_status.items():
        if status in ("flagged", "suspicious"):
            name = function_renames.get(addr, "")
            label = f"{status.upper()}: {name}" if name else status.upper()
            bookmarks.append({"address": addr, "status": status, "label": label})
    return bookmarks


# ---------------------------------------------------------------------------
#  Ghidra script generation
# ---------------------------------------------------------------------------

def _build_ghidra_script(
    meta: Dict[str, str],
    renames: Dict[str, Any],
    notes: List[Dict[str, Any]],
    types: Dict[str, Any],
    triage_status: Dict[str, str],
    include_renames: bool,
    include_comments: bool,
    include_types: bool,
    include_bookmarks: bool,
) -> str:
    """Build a Ghidra Python script string from analysis state."""
    lines: List[str] = []

    # Header
    lines.append("# Arkana Analysis Export for Ghidra")
    lines.append(f"# Generated: {meta['timestamp']}")
    lines.append(f"# Source: {meta['filename']} (SHA256: {meta['sha256']})")
    lines.append("#")
    lines.append("# Run this script in Ghidra's Script Manager to apply analysis results.")
    lines.append("# @category Arkana")
    lines.append("# @menupath Tools.Arkana.Apply Analysis")
    lines.append("")
    lines.append("from ghidra.program.model.symbol import SourceType")
    lines.append("from ghidra.program.model.data import (")
    lines.append("    StructureDataType, EnumDataType, CategoryPath,")
    lines.append("    ByteDataType, ShortDataType, IntegerDataType, LongLongDataType,")
    lines.append("    UnsignedByteDataType, UnsignedShortDataType,")
    lines.append("    UnsignedIntegerDataType, UnsignedLongLongDataType,")
    lines.append("    SignedByteDataType, SignedWordDataType,")
    lines.append("    Pointer32DataType, Pointer64DataType,")
    lines.append(")")
    lines.append("from ghidra.program.model.listing import CodeUnit")
    lines.append("")

    # Track counts for summary
    func_renames = renames.get("functions", {})
    var_renames = renames.get("variables", {})
    labels = renames.get("labels", {})
    function_notes = _collect_function_notes(notes) if include_comments else {}
    structs = types.get("structs", {}) if include_types else {}
    enums = types.get("enums", {}) if include_types else {}
    bookmarks = _collect_bookmarks(triage_status, func_renames) if include_bookmarks else []

    # --- apply_renames ---
    lines.append("def apply_renames():")
    lines.append('    """Apply function renames, variable renames, and address labels."""')
    if not include_renames or (not func_renames and not var_renames and not labels):
        lines.append("    pass  # No renames to apply")
    else:
        lines.append("    fm = currentProgram.getFunctionManager()")
        lines.append("    count = 0")
        lines.append("")

        if func_renames:
            lines.append("    # Function renames")
            lines.append("    function_renames = {")
            for addr, name in sorted(func_renames.items()):
                lines.append(f'        "{_escape_python_string(addr)}": "{_escape_python_string(name)}",')
            lines.append("    }")
            lines.append("    for addr_hex, name in function_renames.items():")
            lines.append("        addr = toAddr(addr_hex)")
            lines.append("        func = fm.getFunctionAt(addr)")
            lines.append("        if func:")
            lines.append("            func.setName(name, SourceType.USER_DEFINED)")
            lines.append("            count += 1")
            lines.append('            print("[Arkana]   Renamed function at {} -> {}".format(addr_hex, name))')
            lines.append("        else:")
            lines.append('            print("[Arkana]   WARNING: No function at {} for rename".format(addr_hex))')
            lines.append("")

        if var_renames:
            lines.append("    # Variable renames (via DecompInterface)")
            lines.append("    try:")
            lines.append("        from ghidra.app.decompiler import DecompInterface")
            lines.append("        decomp = DecompInterface()")
            lines.append("        decomp.openProgram(currentProgram)")
            lines.append("        variable_renames = {")
            for func_addr, mappings in sorted(var_renames.items()):
                entries = ", ".join(
                    f'"{_escape_python_string(old)}": "{_escape_python_string(new)}"'
                    for old, new in sorted(mappings.items())
                )
                lines.append(f'            "{_escape_python_string(func_addr)}": {{{entries}}},')
            lines.append("        }")
            lines.append("        for func_addr_hex, mappings in variable_renames.items():")
            lines.append("            func_addr = toAddr(func_addr_hex)")
            lines.append("            func = fm.getFunctionAt(func_addr)")
            lines.append("            if not func:")
            lines.append("                continue")
            lines.append("            results = decomp.decompileFunction(func, 30, monitor)")
            lines.append("            hfunc = results.getHighFunction()")
            lines.append("            if not hfunc:")
            lines.append("                continue")
            lines.append("            sym_map = hfunc.getLocalSymbolMap()")
            lines.append("            for old_name, new_name in mappings.items():")
            lines.append("                for sym in sym_map.getSymbols():")
            lines.append("                    if sym.getName() == old_name:")
            lines.append("                        from ghidra.program.model.pcode import HighFunctionDBUtil")
            lines.append("                        HighFunctionDBUtil.updateDBVariable(sym, new_name, None, SourceType.USER_DEFINED)")
            lines.append("                        count += 1")
            lines.append("                        break")
            lines.append("        decomp.dispose()")
            lines.append("    except Exception as e:")
            lines.append('        print("[Arkana]   WARNING: Variable renames failed: {}".format(e))')
            lines.append("")

        if labels:
            lines.append("    # Address labels")
            lines.append("    st = currentProgram.getSymbolTable()")
            lines.append("    labels = {")
            for addr, info in sorted(labels.items()):
                label_name = info.get("name", "") if isinstance(info, dict) else str(info)
                lines.append(f'        "{_escape_python_string(addr)}": "{_escape_python_string(label_name)}",')
            lines.append("    }")
            lines.append("    for addr_hex, name in labels.items():")
            lines.append("        addr = toAddr(addr_hex)")
            lines.append("        st.createLabel(addr, name, SourceType.USER_DEFINED)")
            lines.append("        count += 1")
            lines.append("")

        lines.append('    print("[Arkana]   Applied {} renames/labels".format(count))')

    lines.append("")
    lines.append("")

    # --- apply_comments ---
    lines.append("def apply_comments():")
    lines.append('    """Apply function notes as plate/pre comments."""')
    if not include_comments or not function_notes:
        lines.append("    pass  # No comments to apply")
    else:
        lines.append("    listing = currentProgram.getListing()")
        lines.append("    count = 0")
        lines.append("    comments = {")
        for addr, text in sorted(function_notes.items()):
            lines.append(f'        "{_escape_python_string(addr)}": "{_escape_python_string(text)}",')
        lines.append("    }")
        lines.append("    for addr_hex, comment in comments.items():")
        lines.append("        addr = toAddr(addr_hex)")
        lines.append("        cu = listing.getCodeUnitAt(addr)")
        lines.append("        if cu:")
        lines.append("            existing = cu.getComment(CodeUnit.PLATE_COMMENT) or ''")
        lines.append("            if existing:")
        lines.append("                comment = existing + '\\n---\\n' + comment")
        lines.append("            cu.setComment(CodeUnit.PLATE_COMMENT, comment)")
        lines.append("            count += 1")
        lines.append("        else:")
        lines.append('            print("[Arkana]   WARNING: No code unit at {} for comment".format(addr_hex))')
        lines.append('    print("[Arkana]   Applied {} comments".format(count))')
    lines.append("")
    lines.append("")

    # --- apply_types ---
    lines.append("def apply_types():")
    lines.append('    """Apply custom struct and enum definitions."""')
    if not include_types or (not structs and not enums):
        lines.append("    pass  # No custom types to apply")
    else:
        lines.append("    dtm = currentProgram.getDataTypeManager()")
        lines.append('    category = CategoryPath("/Arkana")')
        lines.append("    count = 0")
        lines.append("")

        # Ghidra data type size mapping
        _ghidra_type_map = {
            "uint8": ("UnsignedByteDataType", 1),
            "int8": ("SignedByteDataType", 1),
            "uint16_le": ("UnsignedShortDataType", 2),
            "uint16_be": ("UnsignedShortDataType", 2),
            "int16_le": ("ShortDataType", 2),
            "int16_be": ("ShortDataType", 2),
            "uint32_le": ("UnsignedIntegerDataType", 4),
            "uint32_be": ("UnsignedIntegerDataType", 4),
            "int32_le": ("IntegerDataType", 4),
            "int32_be": ("IntegerDataType", 4),
            "uint64_le": ("UnsignedLongLongDataType", 8),
            "uint64_be": ("UnsignedLongLongDataType", 8),
            "int64_le": ("LongLongDataType", 8),
            "int64_be": ("LongLongDataType", 8),
        }

        if structs:
            lines.append("    # Struct definitions")
            for struct_name, struct_def in sorted(structs.items()):
                fields = struct_def.get("fields", [])
                lines.append(f'    # Struct: {_escape_python_string(struct_name)}')
                lines.append(f'    struct = StructureDataType(category, "{_escape_python_string(struct_name)}", 0)')
                for field in fields:
                    fname = field.get("name", "")
                    ftype = field.get("type", "")
                    if ftype.startswith("padding:"):
                        pad_size = int(ftype.split(":")[1])
                        if fname:
                            lines.append(f'    struct.add(ByteDataType.dataType, {pad_size}, "{_escape_python_string(fname)}", "padding")')
                        else:
                            lines.append(f'    struct.add(ByteDataType.dataType, {pad_size}, "padding", "padding")')
                    elif ftype.startswith("bytes:"):
                        byte_count = int(ftype.split(":")[1])
                        field_label = _escape_python_string(fname) if fname else "raw_bytes"
                        lines.append(f'    struct.add(ByteDataType.dataType, {byte_count}, "{field_label}", "raw bytes")')
                    elif ftype in _ghidra_type_map:
                        ghidra_cls, size = _ghidra_type_map[ftype]
                        field_label = _escape_python_string(fname) if fname else ftype
                        lines.append(f'    struct.add({ghidra_cls}.dataType, {size}, "{field_label}", "")')
                    elif ftype in ("cstring", "wstring", "ipv4"):
                        # Variable-length or special — add as pointer-sized placeholder
                        field_label = _escape_python_string(fname) if fname else ftype
                        lines.append(f'    struct.add(Pointer32DataType.dataType, 4, "{field_label}", "{ftype} (placeholder — adjust manually)")')
                    else:
                        # Unknown type — add as 4-byte placeholder
                        field_label = _escape_python_string(fname) if fname else ftype
                        lines.append(f'    struct.add(IntegerDataType.dataType, 4, "{field_label}", "unknown type: {_escape_python_string(ftype)}")')
                lines.append("    dtm.addDataType(struct, None)")
                lines.append("    count += 1")
                lines.append(f'    print("[Arkana]   Created struct: {_escape_python_string(struct_name)}")')
                lines.append("")

        if enums:
            lines.append("    # Enum definitions")
            for enum_name, enum_def in sorted(enums.items()):
                values = enum_def.get("values", {})
                size = enum_def.get("size", 4)
                lines.append(f'    enum = EnumDataType(category, "{_escape_python_string(enum_name)}", {size})')
                for vname, vval in sorted(values.items(), key=lambda x: x[1]):
                    lines.append(f'    enum.add("{_escape_python_string(vname)}", {vval})')
                lines.append("    dtm.addDataType(enum, None)")
                lines.append("    count += 1")
                lines.append(f'    print("[Arkana]   Created enum: {_escape_python_string(enum_name)}")')
                lines.append("")

        lines.append('    print("[Arkana]   Applied {} type definitions".format(count))')
    lines.append("")
    lines.append("")

    # --- apply_bookmarks ---
    lines.append("def apply_bookmarks():")
    lines.append('    """Create bookmarks for flagged/suspicious functions."""')
    if not include_bookmarks or not bookmarks:
        lines.append("    pass  # No bookmarks to apply")
    else:
        lines.append("    bm = currentProgram.getBookmarkManager()")
        lines.append("    count = 0")
        lines.append("    bookmarks = [")
        for bk in bookmarks:
            lines.append(
                f'        {{"address": "{_escape_python_string(bk["address"])}", '
                f'"status": "{_escape_python_string(bk["status"])}", '
                f'"label": "{_escape_python_string(bk["label"])}"}},')
        lines.append("    ]")
        lines.append("    for bk in bookmarks:")
        lines.append('        addr = toAddr(bk["address"])')
        lines.append('        category = "Arkana-" + bk["status"]')
        lines.append('        bm.setBookmark(addr, "Analysis", category, bk["label"])')
        lines.append("        count += 1")
        lines.append('    print("[Arkana]   Created {} bookmarks".format(count))')
    lines.append("")
    lines.append("")

    # --- Main execution ---
    lines.append("# Main execution")
    lines.append('if __name__ == "__main__" or True:  # Always run in Ghidra')
    lines.append('    print("[Arkana] Applying analysis results...")')
    sections_applied: List[str] = []
    if include_renames and (func_renames or var_renames or labels):
        lines.append("    apply_renames()")
        sections_applied.append("renames")
    if include_comments and function_notes:
        lines.append("    apply_comments()")
        sections_applied.append("comments")
    if include_types and (structs or enums):
        lines.append("    apply_types()")
        sections_applied.append("types")
    if include_bookmarks and bookmarks:
        lines.append("    apply_bookmarks()")
        sections_applied.append("bookmarks")

    if not sections_applied:
        lines.append('    print("[Arkana] No analysis data to apply.")')
    else:
        parts = ", ".join(sections_applied)
        lines.append(f'    print("[Arkana] Done. Applied: {parts}.")')
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
#  IDA script generation
# ---------------------------------------------------------------------------

def _build_ida_script(
    meta: Dict[str, str],
    renames: Dict[str, Any],
    notes: List[Dict[str, Any]],
    types: Dict[str, Any],
    triage_status: Dict[str, str],
    include_renames: bool,
    include_comments: bool,
    include_types: bool,
) -> str:
    """Build an IDAPython script string from analysis state."""
    lines: List[str] = []

    # Header
    lines.append("# Arkana Analysis Export for IDA Pro")
    lines.append(f"# Generated: {meta['timestamp']}")
    lines.append(f"# Source: {meta['filename']} (SHA256: {meta['sha256']})")
    lines.append("#")
    lines.append("# Run in IDA: File -> Script Command... -> Python")
    lines.append("# Or: File -> Script File...")
    lines.append("")
    lines.append("import idc")
    lines.append("import ida_name")
    lines.append("import ida_bytes")
    lines.append("import ida_funcs")
    lines.append("import idautils")
    lines.append("")

    if include_types:
        lines.append("try:")
        lines.append("    import ida_struct")
        lines.append("    import ida_enum")
        lines.append("    import ida_nalt")
        lines.append("    IDA_TYPES_AVAILABLE = True")
        lines.append("except ImportError:")
        lines.append("    IDA_TYPES_AVAILABLE = False")
        lines.append("")

    func_renames = renames.get("functions", {})
    var_renames = renames.get("variables", {})
    labels = renames.get("labels", {})
    function_notes = _collect_function_notes(notes) if include_comments else {}
    structs = types.get("structs", {}) if include_types else {}
    enums = types.get("enums", {}) if include_types else {}

    # --- apply_renames ---
    lines.append("def apply_renames():")
    lines.append('    """Apply function renames, variable renames, and address labels."""')
    if not include_renames or (not func_renames and not var_renames and not labels):
        lines.append("    pass  # No renames to apply")
    else:
        lines.append("    count = 0")
        lines.append("")

        if func_renames:
            lines.append("    # Function renames")
            lines.append("    function_renames = {")
            for addr, name in sorted(func_renames.items()):
                lines.append(f'        "{_escape_python_string(addr)}": "{_escape_python_string(name)}",')
            lines.append("    }")
            lines.append("    for addr_hex, name in function_renames.items():")
            lines.append("        addr = int(addr_hex, 16)")
            lines.append("        if ida_name.set_name(addr, name, ida_name.SN_NOWARN | ida_name.SN_FORCE):")
            lines.append("            count += 1")
            lines.append("        else:")
            lines.append('            print("[Arkana]   WARNING: Failed to rename at 0x{:x}".format(addr))')
            lines.append("")

        if var_renames:
            lines.append("    # Variable renames")
            lines.append("    # Note: IDA variable renames require decompiler (Hex-Rays).")
            lines.append("    # These are applied as repeatable comments at function addresses instead.")
            lines.append("    variable_renames = {")
            for func_addr, mappings in sorted(var_renames.items()):
                entries = ", ".join(
                    f'"{_escape_python_string(old)}": "{_escape_python_string(new)}"'
                    for old, new in sorted(mappings.items())
                )
                lines.append(f'        "{_escape_python_string(func_addr)}": {{{entries}}},')
            lines.append("    }")
            lines.append("    for func_addr_hex, mappings in variable_renames.items():")
            lines.append("        addr = int(func_addr_hex, 16)")
            lines.append('        rename_text = ", ".join("{} -> {}".format(o, n) for o, n in mappings.items())')
            lines.append('        comment = "[Arkana vars] " + rename_text')
            lines.append("        existing = idc.get_func_cmt(addr, True) or ''")
            lines.append("        if existing:")
            lines.append("            comment = existing + '\\n' + comment")
            lines.append("        idc.set_func_cmt(addr, comment, True)")
            lines.append("        count += 1")
            lines.append("")

        if labels:
            lines.append("    # Address labels")
            lines.append("    labels = {")
            for addr, info in sorted(labels.items()):
                label_name = info.get("name", "") if isinstance(info, dict) else str(info)
                lines.append(f'        "{_escape_python_string(addr)}": "{_escape_python_string(label_name)}",')
            lines.append("    }")
            lines.append("    for addr_hex, name in labels.items():")
            lines.append("        addr = int(addr_hex, 16)")
            lines.append("        ida_name.set_name(addr, name, ida_name.SN_NOWARN)")
            lines.append("        count += 1")
            lines.append("")

        lines.append('    print("[Arkana]   Applied {} renames/labels".format(count))')

    lines.append("")
    lines.append("")

    # --- apply_comments ---
    lines.append("def apply_comments():")
    lines.append('    """Apply function notes as comments."""')
    if not include_comments or not function_notes:
        lines.append("    pass  # No comments to apply")
    else:
        lines.append("    count = 0")
        lines.append("    comments = {")
        for addr, text in sorted(function_notes.items()):
            lines.append(f'        "{_escape_python_string(addr)}": "{_escape_python_string(text)}",')
        lines.append("    }")
        lines.append("    for addr_hex, comment in comments.items():")
        lines.append("        addr = int(addr_hex, 16)")
        lines.append("        # Apply as repeatable function comment")
        lines.append("        existing = idc.get_func_cmt(addr, True) or ''")
        lines.append("        if existing:")
        lines.append("            comment = existing + '\\n---\\n' + comment")
        lines.append("        idc.set_func_cmt(addr, comment, True)")
        lines.append("        # Also set anterior comment at the address")
        lines.append("        ida_bytes.set_cmt(addr, comment[:1024], False)")
        lines.append("        count += 1")
        lines.append('    print("[Arkana]   Applied {} comments".format(count))')
    lines.append("")
    lines.append("")

    # --- apply_types ---
    lines.append("def apply_types():")
    lines.append('    """Apply custom struct and enum definitions."""')
    if not include_types or (not structs and not enums):
        lines.append("    pass  # No custom types to apply")
    else:
        lines.append("    if not IDA_TYPES_AVAILABLE:")
        lines.append('        print("[Arkana]   WARNING: ida_struct/ida_enum not available, skipping types")')
        lines.append("        return")
        lines.append("    count = 0")
        lines.append("")

        # IDA struct field size mapping
        _ida_flag_map = {
            "uint8": ("ida_bytes.byte_flag()", 1),
            "int8": ("ida_bytes.byte_flag()", 1),
            "uint16_le": ("ida_bytes.word_flag()", 2),
            "uint16_be": ("ida_bytes.word_flag()", 2),
            "int16_le": ("ida_bytes.word_flag()", 2),
            "int16_be": ("ida_bytes.word_flag()", 2),
            "uint32_le": ("ida_bytes.dword_flag()", 4),
            "uint32_be": ("ida_bytes.dword_flag()", 4),
            "int32_le": ("ida_bytes.dword_flag()", 4),
            "int32_be": ("ida_bytes.dword_flag()", 4),
            "uint64_le": ("ida_bytes.qword_flag()", 8),
            "uint64_be": ("ida_bytes.qword_flag()", 8),
            "int64_le": ("ida_bytes.qword_flag()", 8),
            "int64_be": ("ida_bytes.qword_flag()", 8),
        }

        if structs:
            lines.append("    # Struct definitions")
            for struct_name, struct_def in sorted(structs.items()):
                fields = struct_def.get("fields", [])
                safe_name = _escape_python_string(struct_name)
                lines.append(f'    # Struct: {safe_name}')
                lines.append(f'    sid = ida_struct.get_struc_id("{safe_name}")')
                lines.append("    if sid != idc.BADADDR:")
                lines.append(f'        print("[Arkana]   Struct {safe_name} already exists, skipping")')
                lines.append("    else:")
                lines.append(f'        sid = ida_struct.add_struc(-1, "{safe_name}", False)')
                lines.append("        if sid != idc.BADADDR:")
                lines.append("            sptr = ida_struct.get_struc(sid)")
                for field in fields:
                    fname = field.get("name", "")
                    ftype = field.get("type", "")
                    if ftype.startswith("padding:"):
                        pad_size = int(ftype.split(":")[1])
                        field_label = _escape_python_string(fname) if fname else "padding"
                        lines.append(f'            ida_struct.add_struc_member(sptr, "{field_label}", idc.BADADDR, ida_bytes.byte_flag(), None, {pad_size})')
                    elif ftype.startswith("bytes:"):
                        byte_count = int(ftype.split(":")[1])
                        field_label = _escape_python_string(fname) if fname else "raw_bytes"
                        lines.append(f'            ida_struct.add_struc_member(sptr, "{field_label}", idc.BADADDR, ida_bytes.byte_flag(), None, {byte_count})')
                    elif ftype in _ida_flag_map:
                        ida_flag, size = _ida_flag_map[ftype]
                        field_label = _escape_python_string(fname) if fname else ftype
                        lines.append(f'            ida_struct.add_struc_member(sptr, "{field_label}", idc.BADADDR, {ida_flag}, None, {size})')
                    else:
                        # Unknown or variable-length — add as 4-byte placeholder
                        field_label = _escape_python_string(fname) if fname else ftype
                        lines.append(f'            ida_struct.add_struc_member(sptr, "{field_label}", idc.BADADDR, ida_bytes.dword_flag(), None, 4)  # placeholder for {_escape_python_string(ftype)}')
                lines.append("            count += 1")
                lines.append(f'            print("[Arkana]   Created struct: {safe_name}")')
                lines.append("")

        if enums:
            lines.append("    # Enum definitions")
            for enum_name, enum_def in sorted(enums.items()):
                values = enum_def.get("values", {})
                size = enum_def.get("size", 4)
                safe_name = _escape_python_string(enum_name)
                # IDA enum width: 0=byte, 1=word, 2=dword, 3=qword
                width_map = {1: 0, 2: 1, 4: 2, 8: 3}
                width = width_map.get(size, 2)
                lines.append(f'    eid = ida_enum.get_enum("{safe_name}")')
                lines.append("    if eid != idc.BADADDR:")
                lines.append(f'        print("[Arkana]   Enum {safe_name} already exists, skipping")')
                lines.append("    else:")
                lines.append(f'        eid = ida_enum.add_enum(-1, "{safe_name}", 0)')
                lines.append("        if eid != idc.BADADDR:")
                lines.append(f"            ida_enum.set_enum_width(eid, {width})")
                for vname, vval in sorted(values.items(), key=lambda x: x[1]):
                    lines.append(f'            ida_enum.add_enum_member(eid, "{_escape_python_string(vname)}", {vval})')
                lines.append("            count += 1")
                lines.append(f'            print("[Arkana]   Created enum: {safe_name}")')
                lines.append("")

        lines.append('    print("[Arkana]   Applied {} type definitions".format(count))')
    lines.append("")
    lines.append("")

    # --- Main execution ---
    lines.append("# Main execution")
    lines.append('print("[Arkana] Applying analysis results...")')
    sections_applied: List[str] = []
    if include_renames and (func_renames or var_renames or labels):
        lines.append("apply_renames()")
        sections_applied.append("renames")
    if include_comments and function_notes:
        lines.append("apply_comments()")
        sections_applied.append("comments")
    if include_types and (structs or enums):
        lines.append("apply_types()")
        sections_applied.append("types")

    if not sections_applied:
        lines.append('print("[Arkana] No analysis data to apply.")')
    else:
        parts = ", ".join(sections_applied)
        lines.append(f'print("[Arkana] Done. Applied: {parts}.")')
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
#  MCP tool: export_ghidra_script
# ---------------------------------------------------------------------------

@tool_decorator
async def export_ghidra_script(
    ctx: Context,
    output_path: str = "",
    include_renames: bool = True,
    include_comments: bool = True,
    include_types: bool = True,
    include_bookmarks: bool = True,
) -> Dict[str, Any]:
    """
    [Phase: 7 — Report] Export analysis results as a Ghidra Python script.

    ---compact: export renames/notes/types as Ghidra Python script | needs: file

    Generates a Python script that can be run in Ghidra's Script Manager
    to apply Arkana's function renames, variable renames, address labels,
    function comments (from notes), custom type definitions, and bookmarks
    for flagged/suspicious functions.

    When to use: After analysis is complete and you want to transfer results
    into Ghidra for further manual review or to share with a team using Ghidra.

    Args:
        ctx: The MCP Context object.
        output_path: (str) File path to save the script. Default: auto-generated
            next to the loaded binary with a _ghidra.py suffix.
        include_renames: (bool) Include function/variable renames and labels (default True).
        include_comments: (bool) Include function notes as plate comments (default True).
        include_types: (bool) Include custom struct/enum definitions (default True).
        include_bookmarks: (bool) Include bookmarks for flagged/suspicious functions (default True).

    Returns:
        A dictionary with script path, size, and summary of exported items.
    """
    _check_pe_loaded("export_ghidra_script")

    meta = _get_file_metadata()

    # Snapshot state data
    renames = state.get_all_renames_snapshot()
    notes = state.get_all_notes_snapshot()
    types = state.get_all_types_snapshot()
    triage_status = state.get_triage_status()

    await ctx.info("Generating Ghidra export script...")

    script_text = _build_ghidra_script(
        meta=meta,
        renames=renames,
        notes=notes,
        types=types,
        triage_status=triage_status,
        include_renames=include_renames,
        include_comments=include_comments,
        include_types=include_types,
        include_bookmarks=include_bookmarks,
    )

    abs_path = _resolve_output_path(output_path, "_ghidra.py")

    artifact_info = _write_script_and_register(
        abs_path, script_text, "export_ghidra_script",
        f"Ghidra script for {meta['filename']}",
    )

    # Build summary counts
    func_renames = renames.get("functions", {}) if include_renames else {}
    var_renames = renames.get("variables", {}) if include_renames else {}
    label_count = len(renames.get("labels", {})) if include_renames else 0
    function_notes = _collect_function_notes(notes) if include_comments else {}
    structs = types.get("structs", {}) if include_types else {}
    enums = types.get("enums", {}) if include_types else {}
    bookmarks = _collect_bookmarks(triage_status, renames.get("functions", {})) if include_bookmarks else []

    summary = {
        "function_renames": len(func_renames),
        "variable_rename_functions": len(var_renames),
        "address_labels": label_count,
        "function_comments": len(function_notes),
        "struct_definitions": len(structs),
        "enum_definitions": len(enums),
        "bookmarks": len(bookmarks),
    }
    total_items = sum(summary.values())

    result = {
        "status": "success",
        "script_path": artifact_info["path"],
        "script_size_bytes": artifact_info["size"],
        "artifact_id": artifact_info["artifact_id"],
        "target_tool": "Ghidra",
        "source_file": meta["filename"],
        "sha256": meta["sha256"],
        "summary": summary,
        "total_items_exported": total_items,
        "hint": f"Open in Ghidra: Script Manager -> Run Script -> {os.path.basename(abs_path)}"
                if total_items > 0 else "Script generated but no analysis data to apply.",
    }
    return await _check_mcp_response_size(ctx, result, "export_ghidra_script")


# ---------------------------------------------------------------------------
#  MCP tool: export_ida_script
# ---------------------------------------------------------------------------

@tool_decorator
async def export_ida_script(
    ctx: Context,
    output_path: str = "",
    include_renames: bool = True,
    include_comments: bool = True,
    include_types: bool = True,
) -> Dict[str, Any]:
    """
    [Phase: 7 — Report] Export analysis results as an IDAPython script.

    ---compact: export renames/notes/types as IDAPython script | needs: file

    Generates a Python script that can be run in IDA Pro's Script Command
    (File -> Script Command... -> Python) to apply Arkana's function renames,
    address comments, and custom type definitions.

    When to use: After analysis is complete and you want to transfer results
    into IDA Pro for further manual review or to share with a team using IDA.

    Note: Variable renames are exported as repeatable function comments since
    IDAPython variable renaming requires the Hex-Rays decompiler API.

    Args:
        ctx: The MCP Context object.
        output_path: (str) File path to save the script. Default: auto-generated
            next to the loaded binary with a _ida.py suffix.
        include_renames: (bool) Include function/variable renames and labels (default True).
        include_comments: (bool) Include function notes as comments (default True).
        include_types: (bool) Include custom struct/enum definitions (default True).

    Returns:
        A dictionary with script path, size, and summary of exported items.
    """
    _check_pe_loaded("export_ida_script")

    meta = _get_file_metadata()

    # Snapshot state data
    renames = state.get_all_renames_snapshot()
    notes = state.get_all_notes_snapshot()
    types = state.get_all_types_snapshot()
    triage_status = state.get_triage_status()

    await ctx.info("Generating IDA Pro export script...")

    script_text = _build_ida_script(
        meta=meta,
        renames=renames,
        notes=notes,
        types=types,
        triage_status=triage_status,
        include_renames=include_renames,
        include_comments=include_comments,
        include_types=include_types,
    )

    abs_path = _resolve_output_path(output_path, "_ida.py")

    artifact_info = _write_script_and_register(
        abs_path, script_text, "export_ida_script",
        f"IDA Pro script for {meta['filename']}",
    )

    # Build summary counts
    func_renames = renames.get("functions", {}) if include_renames else {}
    var_renames = renames.get("variables", {}) if include_renames else {}
    label_count = len(renames.get("labels", {})) if include_renames else 0
    function_notes = _collect_function_notes(notes) if include_comments else {}
    structs = types.get("structs", {}) if include_types else {}
    enums = types.get("enums", {}) if include_types else {}

    summary = {
        "function_renames": len(func_renames),
        "variable_rename_functions": len(var_renames),
        "address_labels": label_count,
        "function_comments": len(function_notes),
        "struct_definitions": len(structs),
        "enum_definitions": len(enums),
    }
    total_items = sum(summary.values())

    result = {
        "status": "success",
        "script_path": artifact_info["path"],
        "script_size_bytes": artifact_info["size"],
        "artifact_id": artifact_info["artifact_id"],
        "target_tool": "IDA Pro",
        "source_file": meta["filename"],
        "sha256": meta["sha256"],
        "summary": summary,
        "total_items_exported": total_items,
        "hint": f"Run in IDA: File -> Script File... -> {os.path.basename(abs_path)}"
                if total_items > 0 else "Script generated but no analysis data to apply.",
    }
    return await _check_mcp_response_size(ctx, result, "export_ida_script")
