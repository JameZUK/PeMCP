"""Dashboard data layer for the PROJECTS tab.

Mirrors the conventions of ``state_api.py`` but reads from
``arkana.projects.project_manager`` rather than ``AnalyzerState``. Functions
return JSON-serialisable dicts ready for the Starlette route handlers in
``arkana/dashboard/app.py``.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from arkana.projects import project_manager, ScratchProject
from arkana.state import get_current_state

logger = logging.getLogger("Arkana")


def _project_card(project) -> Dict[str, Any]:
    """Return a card-shaped summary of a project for the projects grid."""
    m = project.manifest
    primary = m.members.get(m.primary_sha256 or "", {}) if m.primary_sha256 else {}
    last_active = m.members.get(m.last_active_sha256 or "", {}) if m.last_active_sha256 else {}
    return {
        "id": m.id,
        "name": m.name,
        "name_locked": m.name_locked,
        "created_at": m.created_at,
        "last_opened": m.last_opened,
        "tags": list(m.tags),
        "primary_sha256": m.primary_sha256,
        "primary_filename": primary.get("original_filename"),
        "primary_mode": primary.get("mode"),
        "last_active_sha256": m.last_active_sha256,
        "last_active_filename": last_active.get("original_filename"),
        "last_tab": (m.dashboard_state or {}).get("last_tab", ""),
        "member_count": len(m.members),
        "members": [
            {
                "sha256": sha,
                "filename": d.get("original_filename"),
                "size": d.get("size", 0),
                "mode": d.get("mode", "unknown"),
                "added_at": d.get("added_at", 0.0),
                "present": project.member_present(sha),
                "is_primary": (sha == m.primary_sha256),
                "is_last_active": (sha == m.last_active_sha256),
            }
            for sha, d in m.members.items()
        ],
    }


def get_projects_list_data(filter: str = "", tag: str = "",
                           sort_by: str = "last_opened") -> Dict[str, Any]:
    """Return all projects (filtered/sorted) plus the active project's id."""
    projects = project_manager.list(
        filter=filter or "",
        tag=tag or None,
        sort_by=sort_by or "last_opened",
    )
    state = get_current_state()
    active = state.get_active_project() if hasattr(state, "get_active_project") else None
    active_id = None
    active_scratch = False
    if active is not None:
        if getattr(active, "is_scratch", False):
            active_scratch = True
        else:
            active_id = active.id

    return {
        "projects": [_project_card(p) for p in projects],
        "total_count": len(projects),
        "active_project_id": active_id,
        "active_scratch": active_scratch,
        "filters": {"filter": filter, "tag": tag, "sort_by": sort_by},
    }


def get_project_detail_data(project_id: str) -> Optional[Dict[str, Any]]:
    """Return full detail for a single project."""
    proj = project_manager.get(project_id)
    if proj is None:
        return None
    return _project_card(proj)


def get_active_project_data() -> Dict[str, Any]:
    """Report whatever project is currently bound to state."""
    state = get_current_state()
    active = state.get_active_project() if hasattr(state, "get_active_project") else None
    if active is None:
        return {"active": False, "scratch": False, "project": None}
    if getattr(active, "is_scratch", False):
        return {
            "active": True,
            "scratch": True,
            "project": {
                "id": active.id,
                "name": active.name,
                "primary_sha256": active.primary_sha256,
                "last_active_sha256": active.last_active_sha256,
                "members": [
                    {"sha256": sha, "filename": m.original_filename}
                    for sha, m in active.members.items()
                ],
            },
        }
    return {"active": True, "scratch": False, "project": _project_card(active)}


def create_project_data(name: str, tags: Optional[List[str]] = None) -> Dict[str, Any]:
    """Create a new (empty) project. Used by the dashboard "New project" button."""
    proj = project_manager.create(name=name, name_locked=True, tags=tags or [])
    return {"status": "success", "project": _project_card(proj)}


def rename_project_data(project_id: str, new_name: str) -> Dict[str, Any]:
    """Rename a project (sets name_locked=True)."""
    proj = project_manager.get(project_id)
    if proj is None:
        return {"error": f"Project {project_id} not found"}
    project_manager.rename(proj, new_name)
    return {"status": "success", "project": _project_card(proj)}


def tag_project_data(project_id: str, add: Optional[List[str]] = None,
                     remove: Optional[List[str]] = None,
                     replace: bool = False) -> Dict[str, Any]:
    """Add or remove tags."""
    proj = project_manager.get(project_id)
    if proj is None:
        return {"error": f"Project {project_id} not found"}
    if replace:
        proj.add_tags(add or [], replace=True)
    else:
        if add:
            proj.add_tags(add, replace=False)
        if remove:
            proj.remove_tags(remove)
    return {"status": "success", "project": _project_card(proj)}


def delete_project_data(project_id: str) -> Dict[str, Any]:
    """Delete a project (irreversible)."""
    proj = project_manager.get(project_id)
    if proj is None:
        return {"error": f"Project {project_id} not found"}
    state = get_current_state()
    active = state.get_active_project() if hasattr(state, "get_active_project") else None
    if active is proj:
        try:
            state.flush_overlay()
        except Exception:
            pass
        try:
            state.unbind_project()
        except Exception:
            pass
    project_manager.delete(proj)
    return {"status": "success", "deleted_id": project_id}


def set_primary_binary_data(project_id: str, sha256: str) -> Dict[str, Any]:
    """Change the primary binary for a project."""
    proj = project_manager.get(project_id)
    if proj is None:
        return {"error": f"Project {project_id} not found"}
    try:
        proj.set_primary(sha256)
    except ValueError as e:
        return {"error": str(e)}
    return {"status": "success", "project": _project_card(proj)}


def list_importable_archives() -> Dict[str, Any]:
    """Scan known output directories for *.arkana_project.tar.gz files
    that aren't already imported as projects.

    Searches the user's configured export dir (ARKANA_EXPORT_DIR / /output
    in the container) and falls back to the default project output/ dir
    next to the source tree. Each archive is described with name, size,
    mtime, and a flag for whether it's already been imported (heuristic
    based on filename — exact match against existing project names).
    """
    candidates: List[Path] = []
    seen_paths: set = set()

    for env_var in ("ARKANA_EXPORT_DIR", "ARKANA_HOST_EXPORT", "ARKANA_OUTPUT"):
        env_dir = os.environ.get(env_var)
        if env_dir:
            candidates.append(Path(env_dir))
    # Also try the default output dir relative to the source tree
    here = Path(__file__).resolve().parent
    candidates.append(here.parent.parent / "output")
    candidates.append(Path("/output"))

    archives: List[Dict[str, Any]] = []
    existing_names = {p.manifest.name.lower() for p in project_manager.list()}
    for d in candidates:
        try:
            if not d or not d.is_dir():
                continue
            for f in d.iterdir():
                if not f.is_file():
                    continue
                if not f.name.endswith(".arkana_project.tar.gz") and not f.name.endswith(".pemcp_project.tar.gz"):
                    continue
                rp = str(f.resolve())
                if rp in seen_paths:
                    continue
                seen_paths.add(rp)
                stem = f.name.replace(".arkana_project.tar.gz", "").replace(".pemcp_project.tar.gz", "")
                archives.append({
                    "name": f.name,
                    "stem": stem,
                    "path": rp,
                    "size": f.stat().st_size,
                    "mtime": f.stat().st_mtime,
                    "likely_imported": stem.lower() in existing_names,
                })
        except OSError as e:
            logger.debug("list_importable_archives: skipping %s: %s", d, e)
            continue

    archives.sort(key=lambda a: a["mtime"], reverse=True)
    return {"archives": archives, "count": len(archives)}


def import_archive_data(archive_path: str) -> Dict[str, Any]:
    """Import a single .arkana_project.tar.gz archive into a new project.

    Delegates to the existing tools_export.import_project tool's logic but
    extracted as a sync helper for the dashboard route. Both v1 (legacy
    single-binary) and v2 (project-level) archive formats are supported.
    """
    from pathlib import Path as _P
    from arkana.state import get_current_state
    state = get_current_state()
    abs_path = str(_P(archive_path).resolve())
    state.check_path_allowed(abs_path)
    if not os.path.isfile(abs_path):
        return {"error": f"Archive not found: {abs_path}"}
    # Peek at the manifest to determine version
    import tarfile, json as _json, gzip as _gz
    try:
        with tarfile.open(abs_path, "r:gz") as tf:
            try:
                mf = tf.extractfile("manifest.json")
                if mf is None:
                    return {"error": "Archive missing manifest.json"}
                top_manifest = _json.loads(mf.read().decode("utf-8"))
            except KeyError:
                return {"error": "Archive missing manifest.json"}
            export_version = top_manifest.get("export_version", 1)
            if export_version == 2:
                from arkana.mcp.tools_export import _import_project_v2
                return _import_project_v2(abs_path, top_manifest)
            else:
                # v1 archives just register a single project from the wrapper
                # — we replicate the minimal projection here for the dashboard
                # path so the import doesn't depend on the MCP tool's full
                # ctx machinery.
                try:
                    af = tf.extractfile("analysis.json.gz")
                    if af is None:
                        return {"error": "v1 archive missing analysis.json.gz"}
                    wrapper_bytes = _gz.decompress(af.read())
                    wrapper = _json.loads(wrapper_bytes.decode("utf-8"))
                except Exception as e:
                    return {"error": f"v1 archive read failed: {e}"}
                sha256 = top_manifest.get("sha256") or wrapper.get("_cache_meta", {}).get("sha256")
                original_filename = top_manifest.get("original_filename") or wrapper.get("_cache_meta", {}).get("original_filename") or "imported"
                if not sha256:
                    return {"error": "v1 archive missing sha256"}
                # Skip if a project already contains this binary
                existing = project_manager.lookup_by_sha(sha256)
                if existing:
                    return {
                        "status": "already_imported",
                        "project_id": existing[0].id,
                        "project_name": existing[0].name,
                    }
                stem = os.path.splitext(original_filename)[0] or "imported"
                base_name = f"{stem}_{sha256[:8]}"
                name = base_name
                counter = 2
                while project_manager.find_by_name(name):
                    name = f"{base_name}_{counter}"
                    counter += 1
                project = project_manager.create(name=name, name_locked=False, tags=["imported"])
                # Stub member (binary file is in the archive but we don't
                # extract it here — opening the original binary later will
                # adopt it via adopt_binary_into_stub).
                from arkana.projects import ProjectMember, _safe_filename
                stub_name = f"{sha256[:16]}_{_safe_filename(original_filename)}"
                stub_path = project.binaries_dir / stub_name
                project.binaries_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                member = ProjectMember(
                    sha256=sha256,
                    original_filename=original_filename,
                    copy_path=str(stub_path),
                    added_at=__import__("time").time(),
                    size=int(top_manifest.get("original_file_size") or 0),
                    mode=top_manifest.get("mode", "unknown"),
                )
                with project._lock:
                    project.manifest.members[sha256] = member.to_dict()
                    project.manifest.primary_sha256 = sha256
                    project.manifest.last_active_sha256 = sha256
                    project.save_manifest()
                # Save the wrapper's user state as the project's overlay
                overlay = {
                    "notes": wrapper.get("notes") or [],
                    "tool_history": wrapper.get("tool_history") or [],
                    "artifacts": wrapper.get("artifacts") or [],
                    "renames": wrapper.get("renames") or {},
                    "custom_types": wrapper.get("custom_types") or {},
                    "triage_status": wrapper.get("triage_status") or {},
                }
                project.save_overlay(sha256, overlay)
                with project_manager._lock:
                    project_manager._save_index()
                return {
                    "status": "success",
                    "import_version": 1,
                    "project_id": project.id,
                    "project_name": project.name,
                    "member_count": 1,
                }
    except (tarfile.TarError, OSError) as e:
        return {"error": f"Failed to read archive: {e}"}


def save_dashboard_state(project_id: str, key: str, value: Any) -> Dict[str, Any]:
    """Persist a small piece of dashboard state into the project manifest.

    Used for "resume where I left off" — last_tab, hex_offset, last_function.
    Keys are restricted to a known whitelist to keep manifests small.
    """
    _ALLOWED = {"last_tab", "hex_offset", "last_function_address",
                "functions_scroll", "callgraph_layout"}
    if key not in _ALLOWED:
        return {"error": f"Unknown dashboard_state key: {key}"}
    proj = project_manager.get(project_id)
    if proj is None:
        return {"error": f"Project {project_id} not found"}
    proj.set_dashboard_state(key, value)
    return {"status": "success"}
