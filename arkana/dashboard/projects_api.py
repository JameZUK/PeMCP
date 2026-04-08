"""Dashboard data layer for the PROJECTS tab.

Mirrors the conventions of ``state_api.py`` but reads from
``arkana.projects.project_manager`` rather than ``AnalyzerState``. Functions
return JSON-serialisable dicts ready for the Starlette route handlers in
``arkana/dashboard/app.py``.
"""
from __future__ import annotations

import json
import logging
import os
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from arkana.projects import project_manager, ScratchProject
from arkana.state import get_current_state

logger = logging.getLogger("Arkana")


def _project_card_summary(project) -> Dict[str, Any]:
    """Return a lightweight project summary for the projects grid.

    Excludes the per-member breakdown — the grid only displays primary
    filename, member count, and tags. Use ``_project_card_detail`` for the
    expandable view that needs the full member list. This split halves the
    payload size of ``GET /api/projects`` and avoids per-member presence
    checks (which would each acquire ``Project._lock`` and ``stat()`` the
    copy path).
    """
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
    }


def _project_card_detail(project) -> Dict[str, Any]:
    """Return the full project card including a per-member breakdown.

    Uses ``Project.snapshot_members_with_presence`` for the lock-once
    snapshot, then runs the per-member ``os.path.isfile`` check OUTSIDE
    the lock so disk I/O doesn't block other readers.
    """
    summary = _project_card_summary(project)
    members_snapshot, primary_sha, last_active_sha = project.snapshot_members_with_presence()
    summary["members"] = [
        {
            "sha256": m["sha256"],
            "filename": m["filename"],
            "size": m["size"],
            "mode": m["mode"],
            "added_at": m["added_at"],
            "present": bool(m["copy_path"]) and os.path.isfile(m["copy_path"]),
            "is_primary": (m["sha256"] == primary_sha),
            "is_last_active": (m["sha256"] == last_active_sha),
        }
        for m in members_snapshot
    ]
    return summary


def get_projects_list_data(filter: str = "", tag: str = "",
                           sort_by: str = "last_opened") -> Dict[str, Any]:
    """Return all projects (filtered/sorted) plus the active project's id.

    Returns *summaries* (no per-member breakdown). Use ``get_project_detail_data``
    when the user expands a project card to see its members.
    """
    projects = project_manager.list(
        filter=filter or "",
        tag=tag or None,
        sort_by=sort_by or "last_opened",
    )
    st = get_current_state()
    active = st.get_active_project() if hasattr(st, "get_active_project") else None
    active_id = None
    active_scratch = False
    if active is not None:
        if getattr(active, "is_scratch", False):
            active_scratch = True
        else:
            active_id = active.id

    return {
        "projects": [_project_card_summary(p) for p in projects],
        "total_count": len(projects),
        "active_project_id": active_id,
        "active_scratch": active_scratch,
        "filters": {"filter": filter, "tag": tag, "sort_by": sort_by},
    }


def get_project_detail_data(project_id: str) -> Optional[Dict[str, Any]]:
    """Return full detail for a single project (including member list)."""
    proj = project_manager.get(project_id)
    if proj is None:
        return None
    return _project_card_detail(proj)


def get_active_project_data() -> Dict[str, Any]:
    """Report whatever project is currently bound to state."""
    st = get_current_state()
    active = st.get_active_project() if hasattr(st, "get_active_project") else None
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
    return {"active": True, "scratch": False, "project": _project_card_detail(active)}


def create_project_data(name: str, tags: Optional[List[str]] = None) -> Dict[str, Any]:
    """Create a new (empty) project. Used by the dashboard "New project" button."""
    proj = project_manager.create(name=name, name_locked=True, tags=tags or [])
    return {"status": "success", "project": _project_card_summary(proj)}


def rename_project_data(project_id: str, new_name: str) -> Dict[str, Any]:
    """Rename a project (sets name_locked=True)."""
    proj = project_manager.get(project_id)
    if proj is None:
        return {"error": f"Project {project_id} not found"}
    project_manager.rename(proj, new_name)
    return {"status": "success", "project": _project_card_summary(proj)}


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
    return {"status": "success", "project": _project_card_summary(proj)}


def delete_project_data(project_id: str) -> Dict[str, Any]:
    """Delete a project (irreversible)."""
    proj = project_manager.get(project_id)
    if proj is None:
        return {"error": f"Project {project_id} not found"}
    st = get_current_state()
    active = st.get_active_project() if hasattr(st, "get_active_project") else None
    if active is proj:
        try:
            st.flush_overlay()
        except Exception:
            pass
        try:
            st.unbind_project()
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
    return {"status": "success", "project": _project_card_summary(proj)}


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
    seen_paths: Set[str] = set()

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
                # One stat() call covers both size and mtime.
                st = f.stat()
                archives.append({
                    "name": f.name,
                    "stem": stem,
                    "path": rp,
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                    "likely_imported": stem.lower() in existing_names,
                })
        except OSError as e:
            logger.debug("list_importable_archives: skipping %s: %s", d, e)
            continue

    archives.sort(key=lambda a: a["mtime"], reverse=True)
    return {"archives": archives, "count": len(archives)}


def import_archive_data(archive_path: str) -> Dict[str, Any]:
    """Import a v2 .arkana_project.tar.gz archive into a new project.

    Sync wrapper around ``tools_export._import_project_v2`` for the dashboard
    route. Only v2 (project-level) archives are accepted — v1 single-binary
    session exports were retired with the cache → project overlay split.
    """
    st = get_current_state()
    abs_path = str(Path(archive_path).resolve())
    st.check_path_allowed(abs_path)
    if not os.path.isfile(abs_path):
        return {"error": f"Archive not found: {abs_path}"}
    try:
        with tarfile.open(abs_path, "r:gz") as tf:
            try:
                mf = tf.extractfile("manifest.json")
                if mf is None:
                    return {"error": "Archive missing manifest.json"}
                top_manifest = json.loads(mf.read().decode("utf-8"))
            except KeyError:
                return {"error": "Archive missing manifest.json"}
    except (tarfile.TarError, OSError) as e:
        return {"error": f"Failed to read archive: {e}"}
    if not isinstance(top_manifest, dict):
        return {"error": "Invalid manifest.json contents"}
    export_version = top_manifest.get("export_version")
    if export_version != 2:
        return {
            "error": (
                f"Unsupported archive format (export_version={export_version!r}). "
                "Only v2 project archives are supported."
            )
        }
    from arkana.mcp.tools_export import _import_project_v2
    try:
        return _import_project_v2(abs_path, top_manifest)
    except Exception as e:
        return {"error": f"Import failed: {e}"}


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
