"""MCP tools for project management.

A "project" is a named container that groups one or more binaries with their
user-mutable analysis state (notes, artifacts, renames, custom types, triage
flags, coverage, sandbox reports). Projects sit on top of the SHA256 cache
and store user state in per-binary overlays under ~/.arkana/projects/{id}/.

These tools let the AI list, create, switch, rename, tag, and delete projects,
plus add/remove binaries from multi-binary investigations. The dashboard's
PROJECTS tab is built on the same data layer.

See arkana/projects.py for the underlying implementation.
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Dict, List, Optional

from arkana.config import state, logger, Context
from arkana.mcp.server import tool_decorator
from arkana.projects import (
    project_manager,
    ScratchProject,
    Project,
    _validate_project_name,
)
from arkana.state import TASK_RUNNING, TASK_OVERTIME


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def _project_summary(project: Project) -> Dict[str, Any]:
    """Build a JSON-serialisable summary of a project for tool responses."""
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
        "primary_filename": primary.get("original_filename") if primary else None,
        "last_active_sha256": m.last_active_sha256,
        "last_active_filename": last_active.get("original_filename") if last_active else None,
        "member_count": len(m.members),
        "members": [
            {
                "sha256": sha,
                "filename": d.get("original_filename"),
                "size": d.get("size", 0),
                "mode": d.get("mode", "unknown"),
                "added_at": d.get("added_at", 0.0),
                "present": project.member_present(sha),
            }
            for sha, d in m.members.items()
        ],
    }


def _resolve_project(id_or_name: Optional[str]) -> Project:
    """Resolve a project by id-or-name. Falls back to active if id_or_name is None."""
    if id_or_name:
        proj = project_manager.resolve(id_or_name)
        if proj is None:
            raise ValueError(f"No project found matching {id_or_name!r}")
        return proj
    active = state.get_active_project()
    if active is None or getattr(active, "is_scratch", False):
        raise ValueError(
            "No active on-disk project. Pass project='<id-or-name>' or open a binary "
            "and add a note/artifact to promote the scratch project to disk."
        )
    return active


def _check_no_background_tasks() -> Optional[Dict[str, Any]]:
    """Return an error dict if background tasks are running, else None."""
    active = []
    for tid in state.get_all_task_ids():
        t = state.get_task(tid)
        if t and t.get("status") in (TASK_RUNNING, TASK_OVERTIME):
            active.append(f"{tid} ({t.get('status')})")
    if active:
        return {
            "error": (
                f"Cannot switch projects: {len(active)} background task(s) still active: "
                f"{', '.join(active[:5])}."
            ),
            "active_tasks": active,
            "hint": "Use abort_background_task() to stop them first, or pass force_switch=True.",
        }
    return None


# ---------------------------------------------------------------------------
#  Tools
# ---------------------------------------------------------------------------

@tool_decorator
async def list_projects(
    ctx: Context,
    filter: str = "",
    tag: str = "",
    sort_by: str = "last_opened",
    limit: int = 50,
) -> Dict[str, Any]:
    """
    [Phase: utility] List all Arkana projects with summary metadata.

    ---compact: list projects with name, primary binary, last opened, member count

    Args:
        ctx: MCP Context.
        filter: (str) Substring filter on name or tag (case-insensitive).
        tag: (str) Only return projects carrying this exact tag.
        sort_by: (str) 'last_opened' (default), 'name', or 'created_at'.
        limit: (int) Maximum projects to return (default 50, hard cap 1000).

    Returns:
        {projects: [...], total_count: int, active_project_id: <id-or-None>}
    """
    limit = max(1, min(int(limit), 1000))
    projects = project_manager.list(filter=filter or "", tag=tag or None, sort_by=sort_by)
    total = len(projects)
    projects = projects[:limit]
    active = state.get_active_project()
    active_id = active.id if active is not None and not getattr(active, "is_scratch", False) else None
    return {
        "projects": [_project_summary(p) for p in projects],
        "total_count": total,
        "active_project_id": active_id,
    }


@tool_decorator
async def current_project(ctx: Context) -> Dict[str, Any]:
    """
    [Phase: utility] Return the currently active project (if any) and its active binary.

    ---compact: report the active project and currently loaded binary

    Returns:
        {active: bool, project: <summary or None>, scratch: bool}
    """
    active = state.get_active_project()
    if active is None:
        return {"active": False, "project": None, "scratch": False, "hint": "No file loaded yet."}
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
                "hint": (
                    "This is a scratch project — it will be promoted to disk on the "
                    "first state mutation (note, artifact, rename, triage flag, etc.). "
                    "Call create_project() or rename_project() to give it an explicit name."
                ),
            },
        }
    return {"active": True, "scratch": False, "project": _project_summary(active)}


@tool_decorator
async def create_project(
    ctx: Context,
    name: str,
    binary_paths: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    [Phase: utility] Create a new project with an explicit name.

    ---compact: create a new project | optionally seeded with binaries | sets name_locked

    The project is created immediately on disk. If binary_paths is provided,
    each binary is hashed and adopted into the project's binaries/ directory;
    the first becomes the primary binary. The created project does NOT become
    the active project — call open_project() or open_file() to load a member.

    Args:
        ctx: MCP Context.
        name: (str) Project name. Must be ≤100 chars; allowed chars are letters,
            digits, spaces, underscores, dots, and hyphens. Must be unique.
        binary_paths: (Optional[List[str]]) Optional list of binary file paths
            to add to the project at creation time.
        tags: (Optional[List[str]]) Optional list of free-form tags.

    Returns:
        {status, project: <summary>}
    """
    name = _validate_project_name(name)
    paths = binary_paths or []
    if not isinstance(paths, list):
        raise ValueError("binary_paths must be a list of strings")

    def _create():
        proj = project_manager.create(name=name, name_locked=True, tags=tags or [])
        for p in paths:
            try:
                state.check_path_allowed(str(p))
                project_manager.add_binary(proj, p)
            except Exception as e:
                logger.warning("create_project: failed to add binary %s: %s", p, e)
        return proj

    project = await asyncio.to_thread(_create)
    return {"status": "success", "project": _project_summary(project)}


@tool_decorator
async def open_project(
    ctx: Context,
    project: str,
    binary_sha256: str = "",
    force_switch: bool = False,
) -> Dict[str, Any]:
    """
    [Phase: load] Activate a project and load one of its binaries.

    ---compact: switch to project | loads last-active binary or specified sha256 | needs no file

    The active binary is chosen as: (1) ``binary_sha256`` if provided, else
    (2) the project's last_active_sha256 if set, else (3) primary_sha256.
    Background tasks must be quiesced (use abort_background_task or
    force_switch=True). The actual loading delegates to ``open_file`` so all
    standard analysis runs against the chosen binary.

    Args:
        ctx: MCP Context.
        project: (str) Project ID or name.
        binary_sha256: (str) Optional sha256 of a specific member to load.
        force_switch: (bool) Switch even with active background tasks.
    """
    proj = _resolve_project(project)
    if not force_switch:
        block = _check_no_background_tasks()
        if block:
            return block
    target_sha = (binary_sha256 or "").strip().lower()
    if target_sha:
        if not proj.has_member(target_sha):
            return {"error": f"Binary {target_sha[:12]} is not a member of project {proj.name}"}
        chosen = target_sha
    else:
        chosen = proj.manifest.last_active_sha256 or proj.manifest.primary_sha256
    if not chosen:
        return {"error": f"Project {proj.name} has no binaries to open"}
    member = proj.get_member(chosen)
    if member is None:
        return {"error": f"Member {chosen[:12]} missing from project manifest"}
    binary_path = member.copy_path
    if not binary_path or not os.path.isfile(binary_path):
        return {
            "error": (
                f"Project member {chosen[:12]} has no binary file on disk. "
                "Call open_file() with the original binary path to adopt it."
            ),
            "expected_filename": member.original_filename,
        }
    # Bind project ahead of open_file so resolution finds the active project.
    state.bind_project(proj)
    from arkana.mcp.tools_pe import open_file as _open_file_tool
    result = await _open_file_tool(ctx, binary_path, force_switch=force_switch)
    if isinstance(result, dict):
        result["project"] = _project_summary(proj)
    return result


@tool_decorator
async def close_project(ctx: Context) -> Dict[str, Any]:
    """
    [Phase: utility] Flush and unbind the active project.

    ---compact: flush active project overlay and clear binding | safe no-op if none

    The currently loaded binary is also closed (calls close_file).
    """
    proj = state.get_active_project()
    if proj is None:
        return {"status": "no_project", "message": "No active project."}
    name = proj.name
    if not getattr(proj, "is_scratch", False):
        try:
            state.flush_overlay()
        except Exception as e:
            logger.warning("close_project: flush failed: %s", e)
    from arkana.mcp.tools_pe import close_file as _close_file_tool
    await _close_file_tool(ctx)
    state.unbind_project()
    return {"status": "success", "closed_project": name}


@tool_decorator
async def rename_project(
    ctx: Context,
    project: str,
    new_name: str,
) -> Dict[str, Any]:
    """
    [Phase: utility] Rename a project. Sets name_locked so future auto-rename hints are suppressed.

    ---compact: rename project to new_name | validates uniqueness | sets name_locked

    Args:
        project: ID or current name.
        new_name: New name (must be unique, ≤100 chars).
    """
    proj = _resolve_project(project)
    project_manager.rename(proj, new_name)
    return {"status": "success", "project": _project_summary(proj)}


@tool_decorator
async def tag_project(
    ctx: Context,
    project: str,
    add: Optional[List[str]] = None,
    remove: Optional[List[str]] = None,
    replace: bool = False,
) -> Dict[str, Any]:
    """
    [Phase: utility] Add or remove tags on a project.

    ---compact: add/remove/replace tags on a project

    Args:
        project: ID or name.
        add: tags to add.
        remove: tags to remove.
        replace: when True, replace all existing tags with *add*.
    """
    proj = _resolve_project(project)
    if replace:
        proj.add_tags(add or [], replace=True)
    else:
        if add:
            proj.add_tags(add, replace=False)
        if remove:
            proj.remove_tags(remove)
    return {"status": "success", "project": _project_summary(proj)}


@tool_decorator
async def delete_project(
    ctx: Context,
    project: str,
    confirm: bool = False,
) -> Dict[str, Any]:
    """
    [Phase: utility] Delete a project and all its binaries, artifacts, and overlays.

    ---compact: delete project | requires confirm=True | irreversible

    Returns a dry-run summary when confirm=False (default).
    """
    proj = _resolve_project(project)
    summary = _project_summary(proj)
    if not confirm:
        return {
            "status": "dry_run",
            "would_delete": summary,
            "hint": "Pass confirm=True to actually delete the project.",
        }
    if state.get_active_project() is proj:
        try:
            state.flush_overlay()
        except Exception:
            pass
        state.unbind_project()
    project_manager.delete(proj)
    return {"status": "success", "deleted": summary}


@tool_decorator
async def add_binary_to_project(
    ctx: Context,
    binary_path: str,
    project: str = "",
) -> Dict[str, Any]:
    """
    [Phase: utility] Add a binary to a project (defaults to the active project).

    ---compact: add a binary file to a project | hashes and copies into binaries/

    Args:
        binary_path: Path to the binary to add.
        project: ID or name of the destination project. Defaults to the active project.
    """
    state.check_path_allowed(str(binary_path))
    proj = _resolve_project(project or None)
    if not os.path.isfile(binary_path):
        raise FileNotFoundError(f"Binary not found: {binary_path}")
    member = await asyncio.to_thread(project_manager.add_binary, proj, binary_path)
    return {
        "status": "success",
        "project": _project_summary(proj),
        "added": {
            "sha256": member.sha256,
            "filename": member.original_filename,
            "size": member.size,
        },
    }


@tool_decorator
async def remove_binary_from_project(
    ctx: Context,
    binary_sha256: str,
    project: str = "",
) -> Dict[str, Any]:
    """
    [Phase: utility] Remove a binary from a project.

    ---compact: remove a binary by sha256 | refuses primary binary | needs another primary first
    """
    proj = _resolve_project(project or None)
    sha = (binary_sha256 or "").strip().lower()
    project_manager.remove_binary(proj, sha)
    return {"status": "success", "project": _project_summary(proj)}


@tool_decorator
async def set_primary_binary(
    ctx: Context,
    binary_sha256: str,
    project: str = "",
) -> Dict[str, Any]:
    """
    [Phase: utility] Set the primary binary for a project.

    ---compact: change which member is the primary binary
    """
    proj = _resolve_project(project or None)
    sha = (binary_sha256 or "").strip().lower()
    proj.set_primary(sha)
    return {"status": "success", "project": _project_summary(proj)}
