"""MCP tools for managing artifacts in the active project.

Artifacts are extracted/produced files (carved payloads, decrypted blobs,
generated scripts, sandbox configs, YARA rules, CTI reports, etc.) tracked
on the active session/project. Most artifacts are *created* by other tools
(refinery, payload, crypto, dotnet deob, frida, pe forensic) which call into
``_write_output_and_register_artifact`` or ``_register_artifact_directory``.

These tools let the AI inspect and curate artifacts after the fact:
update descriptions, tag them, attach long-form notes, list/filter them,
and delete ones that turned out to be uninteresting.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from arkana.config import state, Context
from arkana.mcp.server import tool_decorator


def _artifact_summary(art: Dict[str, Any]) -> Dict[str, Any]:
    """Return a JSON-serialisable summary of an artifact for tool responses."""
    out = {
        "id": art.get("id"),
        "kind": art.get("kind", "file"),
        "path": art.get("path"),
        "original_path": art.get("original_path"),
        "sha256": art.get("sha256"),
        "md5": art.get("md5"),
        "size": art.get("size", 0),
        "source_tool": art.get("source_tool"),
        "description": art.get("description", ""),
        "detected_type": art.get("detected_type"),
        "tags": list(art.get("tags") or []),
        "notes": art.get("notes", ""),
        "created_at": art.get("created_at"),
        "modified_at": art.get("modified_at"),
    }
    if art.get("kind") == "directory":
        out["member_count"] = art.get("member_count", 0)
        out["total_size"] = art.get("total_size", 0)
    return out


@tool_decorator
async def list_project_artifacts(
    ctx: Context,
    filter: str = "",
    kind: str = "",
    source_tool: str = "",
    tag: str = "",
    limit: int = 100,
) -> Dict[str, Any]:
    """
    [Phase: utility] List artifacts on the active session, with optional filters.

    ---compact: list session artifacts | filter by kind/tool/tag/text

    Filters compose with AND semantics. Empty filters are ignored.

    Args:
        filter: case-insensitive substring match against name/description/tags.
        kind: 'file' or 'directory' (default: any).
        source_tool: only artifacts produced by this tool name.
        tag: only artifacts carrying this exact tag.
        limit: max entries to return (default 100, hard cap 1000).

    Returns:
        {artifacts: [...], total_count: int}
    """
    limit = max(1, min(int(limit), 1000))
    artifacts = state.get_all_artifacts_snapshot()

    if kind:
        artifacts = [a for a in artifacts if (a.get("kind") or "file") == kind]
    if source_tool:
        artifacts = [a for a in artifacts if a.get("source_tool") == source_tool]
    if tag:
        artifacts = [a for a in artifacts if tag in (a.get("tags") or [])]
    if filter:
        f = filter.lower()
        artifacts = [
            a for a in artifacts
            if f in (a.get("description") or "").lower()
            or f in (a.get("path") or "").lower()
            or f in (a.get("original_path") or "").lower()
            or f in (a.get("notes") or "").lower()
            or any(f in (t or "").lower() for t in (a.get("tags") or []))
        ]

    total = len(artifacts)
    artifacts = artifacts[:limit]
    return {
        "artifacts": [_artifact_summary(a) for a in artifacts],
        "total_count": total,
    }


@tool_decorator
async def update_artifact_metadata(
    ctx: Context,
    artifact_id: str,
    description: str = "",
    tags: Optional[List[str]] = None,
    notes: str = "",
    replace_tags: bool = False,
) -> Dict[str, Any]:
    """
    [Phase: utility] Update an artifact's curatable metadata.

    ---compact: update description/tags/notes on an artifact

    Args:
        artifact_id: ID of the artifact (from register / list output).
        description: replaces if non-empty.
        tags: list to add (or replace if replace_tags=True).
        notes: replaces if non-empty.
        replace_tags: when True, replaces existing tags entirely with *tags*.

    Returns the updated artifact summary.
    """
    updated = state.update_artifact_metadata(
        artifact_id,
        description=description if description else None,
        tags=tags if tags is not None else None,
        notes=notes if notes else None,
        replace_tags=replace_tags,
    )
    if updated is None:
        return {"error": f"Artifact {artifact_id} not found"}
    return {"status": "success", "artifact": _artifact_summary(updated)}


@tool_decorator
async def delete_artifact(
    ctx: Context,
    artifact_id: str,
) -> Dict[str, Any]:
    """
    [Phase: utility] Delete an artifact registration from the session.

    ---compact: delete artifact registration | does NOT delete the file on disk

    The on-disk file (in the project's artifacts/ directory or wherever it
    was originally written) is left in place. To delete the file too,
    remove it manually with your shell.
    """
    if state.delete_artifact(artifact_id):
        return {"status": "success", "artifact_id": artifact_id}
    return {"error": f"Artifact {artifact_id} not found"}
