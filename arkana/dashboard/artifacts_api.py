"""Dashboard data layer for the ARTIFACTS tab.

Reads artifacts from the active session's ``state.artifacts`` (which already
mirror the project overlay when an on-disk project is bound). Provides
filtering, summarisation, and CRUD support for the artifacts page.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from arkana.state import get_current_state

logger = logging.getLogger("Arkana")


def _artifact_row(art: Dict[str, Any]) -> Dict[str, Any]:
    """Return a row-shaped artifact summary for the dashboard table."""
    sha256 = art.get("sha256") or ""
    short_sha = sha256[:12] + "..." if sha256 else ""
    return {
        "id": art.get("id"),
        "kind": art.get("kind", "file"),
        "name": os.path.basename(art.get("path", "")) or "(unnamed)",
        "path": art.get("path"),
        "original_path": art.get("original_path"),
        "sha256": sha256,
        "short_sha": short_sha,
        "md5": art.get("md5"),
        "size": int(art.get("size", 0)),
        "source_tool": art.get("source_tool", ""),
        "description": art.get("description", ""),
        "detected_type": art.get("detected_type", ""),
        "tags": list(art.get("tags") or []),
        "notes": art.get("notes", ""),
        "created_at": art.get("created_at", ""),
        "modified_at": art.get("modified_at", ""),
        "member_count": int(art.get("member_count", 0)),
        "total_size": int(art.get("total_size", 0)),
    }


def get_artifacts_list_data(filter: str = "", kind: str = "",
                            source_tool: str = "", tag: str = "",
                            sort_by: str = "created_at",
                            limit: int = 500) -> Dict[str, Any]:
    """Return filtered + sorted artifacts plus aggregate counts."""
    state = get_current_state()
    artifacts = state.get_all_artifacts_snapshot() if hasattr(state, "get_all_artifacts_snapshot") else []

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
            or f in (a.get("detected_type") or "").lower()
        ]

    # Sorting
    if sort_by == "name":
        artifacts.sort(key=lambda a: os.path.basename(a.get("path", "")).lower())
    elif sort_by == "size":
        artifacts.sort(key=lambda a: int(a.get("size", 0)), reverse=True)
    elif sort_by == "modified_at":
        artifacts.sort(key=lambda a: a.get("modified_at") or a.get("created_at") or "", reverse=True)
    elif sort_by == "source_tool":
        artifacts.sort(key=lambda a: (a.get("source_tool") or "").lower())
    else:
        artifacts.sort(key=lambda a: a.get("created_at") or "", reverse=True)

    total = len(artifacts)
    limit = max(1, min(int(limit), 5000))
    artifacts = artifacts[:limit]

    # Aggregate counts for the filter sidebar
    full = state.get_all_artifacts_snapshot() if hasattr(state, "get_all_artifacts_snapshot") else []
    kinds_count: Dict[str, int] = {}
    tools_count: Dict[str, int] = {}
    tags_count: Dict[str, int] = {}
    for a in full:
        k = a.get("kind") or "file"
        kinds_count[k] = kinds_count.get(k, 0) + 1
        t = a.get("source_tool") or ""
        if t:
            tools_count[t] = tools_count.get(t, 0) + 1
        for tag_name in (a.get("tags") or []):
            tags_count[tag_name] = tags_count.get(tag_name, 0) + 1

    return {
        "artifacts": [_artifact_row(a) for a in artifacts],
        "total_count": total,
        "filtered_count": len(artifacts),
        "facets": {
            "kinds": [{"name": k, "count": v} for k, v in sorted(kinds_count.items())],
            "tools": [{"name": k, "count": v} for k, v in sorted(tools_count.items(), key=lambda x: -x[1])][:30],
            "tags": [{"name": k, "count": v} for k, v in sorted(tags_count.items(), key=lambda x: -x[1])][:50],
        },
        "filters": {
            "filter": filter, "kind": kind, "source_tool": source_tool,
            "tag": tag, "sort_by": sort_by, "limit": limit,
        },
    }


def get_artifact_detail(artifact_id: str) -> Optional[Dict[str, Any]]:
    """Return full detail for a single artifact, including directory members."""
    state = get_current_state()
    for art in state.get_all_artifacts_snapshot():
        if art.get("id") == artifact_id:
            row = _artifact_row(art)
            # Include the full members list for directory bundles
            if art.get("kind") == "directory":
                row["members"] = list(art.get("members") or [])
            return row
    return None


def update_artifact_metadata_data(artifact_id: str, *,
                                  description: Optional[str] = None,
                                  tags: Optional[List[str]] = None,
                                  notes: Optional[str] = None,
                                  replace_tags: bool = False) -> Dict[str, Any]:
    """Update curatable metadata on an artifact."""
    state = get_current_state()
    updated = state.update_artifact_metadata(
        artifact_id,
        description=description,
        tags=tags,
        notes=notes,
        replace_tags=replace_tags,
    )
    if updated is None:
        return {"error": f"Artifact {artifact_id} not found"}
    return {"status": "success", "artifact": _artifact_row(updated)}


def delete_artifact_data(artifact_id: str) -> Dict[str, Any]:
    """Delete an artifact registration (does NOT delete the file on disk)."""
    state = get_current_state()
    if state.delete_artifact(artifact_id):
        return {"status": "success", "artifact_id": artifact_id}
    return {"error": f"Artifact {artifact_id} not found"}


def bulk_delete_artifacts(artifact_ids: List[str]) -> Dict[str, Any]:
    """Delete multiple artifacts at once. Returns per-id status."""
    state = get_current_state()
    results = {}
    for aid in artifact_ids:
        results[aid] = state.delete_artifact(aid)
    return {
        "status": "success",
        "deleted_count": sum(1 for v in results.values() if v),
        "results": results,
    }


def bulk_tag_artifacts(artifact_ids: List[str], tags: List[str],
                       replace_tags: bool = False) -> Dict[str, Any]:
    """Apply tags to multiple artifacts at once."""
    state = get_current_state()
    updated = 0
    for aid in artifact_ids:
        result = state.update_artifact_metadata(
            aid, tags=tags, replace_tags=replace_tags,
        )
        if result is not None:
            updated += 1
    return {"status": "success", "updated_count": updated}


def get_artifact_file_for_download(artifact_id: str) -> Optional[Dict[str, Any]]:
    """Return path + metadata for downloading an artifact file.

    For ``kind='file'`` artifacts, returns the path on disk. For
    ``kind='directory'`` artifacts, the caller (route handler) is responsible
    for zipping on the fly within the size cap. The data layer just supplies
    the path and size info.
    """
    state = get_current_state()
    for art in state.get_all_artifacts_snapshot():
        if art.get("id") == artifact_id:
            path = art.get("path") or ""
            if not path or not os.path.exists(path):
                return {"error": f"Artifact file not found: {path}"}
            return {
                "id": artifact_id,
                "kind": art.get("kind", "file"),
                "path": path,
                "filename": os.path.basename(path),
                "size": int(art.get("size", 0)),
                "detected_type": art.get("detected_type", ""),
            }
    return None
