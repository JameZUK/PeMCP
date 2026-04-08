"""
Project management for Arkana.

A "project" is a named container that groups one or more binaries together
with their user-mutable analysis state (notes, artifacts, renames, custom
types, triage flags, coverage, sandbox reports). Projects sit *on top* of
the SHA256-keyed analysis cache:

  - The cache (~/.arkana/cache/) holds **derived** analysis output (PE
    headers, triage heuristics, IOCs, MITRE mapping, similarity hashes,
    enrichment results) — read-only data that can be regenerated from the
    binary alone.
  - A project (~/.arkana/projects/{id}/) holds the **user-mutable overlay**
    — notes, artifacts, renames, etc. — keyed per binary (so the same
    binary can appear in two projects with independent overlays).

On-disk layout:

    ~/.arkana/projects/
    ├── index.json                       # {project_id: summary}
    └── {project_id}/                    # uuid4().hex[:16]
        ├── manifest.json                # full project state
        ├── binaries/                    # copies of member binaries
        │   └── {sha256}_{safe_name}
        ├── artifacts/                   # copies of registered artifacts
        │   └── {sha256}_{safe_name}     # files
        │   └── {sha256}_{safe_name}/    # directory artifacts
        └── overlay/                     # per-binary user state
            └── {sha256}.json.gz

ScratchProject is an in-memory variant created on first ``open_file`` when
no project is explicitly active. It is promoted to a real on-disk Project
on the first state mutation (note added, artifact registered, function
renamed, triage flag set, etc.) — see ``ProjectManager.promote_scratch``.

Thread safety: ProjectManager uses a single re-entrant lock for index +
manifest mutations. Per-project overlay reads/writes use atomic file
replacement (tempfile + os.replace). All directories created with mode 0700.
"""
from __future__ import annotations

import gzip
import json
import logging
import os
import re
import shutil
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from arkana.constants import (
    PROJECTS_DIR,
    PROJECT_ID_LEN,
    PROJECT_NAME_RE,
    MAX_PROJECT_NAME_LEN,
    MAX_PROJECTS,
    MAX_BINARIES_PER_PROJECT,
)

logger = logging.getLogger("Arkana")


# ---------------------------------------------------------------------------
#  Constants & helpers
# ---------------------------------------------------------------------------

INDEX_FILE = PROJECTS_DIR / "index.json"
MANIFEST_VERSION = 1
OVERLAY_VERSION = 1

_SAFE_FILENAME_RE = re.compile(r"[^a-zA-Z0-9._\-]")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _safe_filename(name: str, max_len: int = 80) -> str:
    """Sanitize a filename for filesystem use. Empty / dotfiles are normalised."""
    cleaned = _SAFE_FILENAME_RE.sub("_", name)[:max_len]
    if not cleaned or cleaned.startswith("."):
        cleaned = f"file_{cleaned.lstrip('.') or 'unnamed'}"
    return cleaned


def _validate_sha256(sha256: str) -> str:
    sha256 = (sha256 or "").lower().strip()
    if not _SHA256_RE.match(sha256):
        raise ValueError(f"Invalid SHA256: {sha256[:20]}...")
    return sha256


def _validate_project_name(name: str) -> str:
    """Raise ValueError if *name* is not a valid project name."""
    if not isinstance(name, str):
        raise ValueError("Project name must be a string")
    name = name.strip()
    if not name:
        raise ValueError("Project name cannot be empty")
    if len(name) > MAX_PROJECT_NAME_LEN:
        raise ValueError(f"Project name too long (>{MAX_PROJECT_NAME_LEN} chars)")
    if not PROJECT_NAME_RE.match(name):
        raise ValueError(
            "Project name must contain only letters, digits, spaces, "
            "underscores, dots, and hyphens"
        )
    return name


def _atomic_write_json(path: Path, data: Any, *, gzipped: bool = False) -> None:
    """Atomically write *data* as JSON to *path* (gzip-compressed if requested)."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    suffix = ".tmp.gz" if gzipped else ".tmp"
    fd = tempfile.NamedTemporaryFile(
        dir=str(path.parent), suffix=suffix, delete=False,
    )
    tmp = Path(fd.name)
    try:
        fd.close()
        if gzipped:
            with gzip.open(tmp, "wt", encoding="utf-8") as f:
                json.dump(data, f)
        else:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        tmp.replace(path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _read_json(path: Path, *, gzipped: bool = False) -> Optional[Any]:
    """Read JSON from *path*, returning None on missing/corrupt."""
    if not path.exists():
        return None
    try:
        if gzipped:
            with gzip.open(path, "rt", encoding="utf-8") as f:
                return json.load(f)
        else:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except (OSError, json.JSONDecodeError, gzip.BadGzipFile) as e:
        logger.warning("Failed to read %s: %s", path, e)
        return None


def _new_project_id() -> str:
    return uuid.uuid4().hex[:PROJECT_ID_LEN]


def _hardlink_or_copy(src: Path, dst: Path) -> str:
    """Hardlink *src* → *dst* if same filesystem, else copy. Returns 'link' or 'copy'."""
    dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.link(src, dst)
        return "link"
    except OSError:
        shutil.copy2(src, dst)
        return "copy"


def _hash_file(path: Path) -> Tuple[str, int]:
    """Return (sha256, size_bytes) for a file. Streams to avoid loading large files."""
    import hashlib
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


# ---------------------------------------------------------------------------
#  Data classes
# ---------------------------------------------------------------------------

@dataclass
class ProjectMember:
    """A binary that belongs to a project."""
    sha256: str
    original_filename: str
    copy_path: str           # absolute path inside project's binaries/
    added_at: float          # epoch seconds
    size: int = 0
    mode: str = "unknown"    # PE/ELF/Mach-O/shellcode

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ProjectMember":
        return cls(
            sha256=d["sha256"],
            original_filename=d.get("original_filename", "unknown"),
            copy_path=d.get("copy_path", ""),
            added_at=float(d.get("added_at", 0.0)),
            size=int(d.get("size", 0)),
            mode=d.get("mode", "unknown"),
        )


@dataclass
class ProjectManifest:
    """The on-disk manifest for a project."""
    id: str
    name: str
    name_locked: bool = False
    created_at: float = 0.0
    last_opened: float = 0.0
    primary_sha256: Optional[str] = None
    last_active_sha256: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    members: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # sha256 -> ProjectMember dict
    dashboard_state: Dict[str, Any] = field(default_factory=dict)
    manifest_version: int = MANIFEST_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "name_locked": self.name_locked,
            "created_at": self.created_at,
            "last_opened": self.last_opened,
            "primary_sha256": self.primary_sha256,
            "last_active_sha256": self.last_active_sha256,
            "tags": list(self.tags),
            "members": {k: dict(v) for k, v in self.members.items()},
            "dashboard_state": dict(self.dashboard_state),
            "manifest_version": self.manifest_version,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ProjectManifest":
        return cls(
            id=d["id"],
            name=d["name"],
            name_locked=bool(d.get("name_locked", False)),
            created_at=float(d.get("created_at", 0.0)),
            last_opened=float(d.get("last_opened", 0.0)),
            primary_sha256=d.get("primary_sha256"),
            last_active_sha256=d.get("last_active_sha256"),
            tags=list(d.get("tags", [])),
            members={k: dict(v) for k, v in d.get("members", {}).items()},
            dashboard_state=dict(d.get("dashboard_state", {})),
            manifest_version=int(d.get("manifest_version", MANIFEST_VERSION)),
        )


# ---------------------------------------------------------------------------
#  Project
# ---------------------------------------------------------------------------

class Project:
    """A real on-disk project. Use ProjectManager to create/load these."""

    def __init__(self, manifest: ProjectManifest, root: Path):
        self.manifest = manifest
        self.root = root
        self._lock = threading.RLock()

    # ---- properties ----
    @property
    def id(self) -> str:
        return self.manifest.id

    @property
    def name(self) -> str:
        return self.manifest.name

    @property
    def is_scratch(self) -> bool:
        return False

    @property
    def binaries_dir(self) -> Path:
        return self.root / "binaries"

    @property
    def artifacts_dir(self) -> Path:
        return self.root / "artifacts"

    @property
    def overlay_dir(self) -> Path:
        return self.root / "overlay"

    @property
    def manifest_path(self) -> Path:
        return self.root / "manifest.json"

    # ---- members ----
    def get_member(self, sha256: str) -> Optional[ProjectMember]:
        sha256 = _validate_sha256(sha256)
        with self._lock:
            d = self.manifest.members.get(sha256)
            return ProjectMember.from_dict(d) if d else None

    def has_member(self, sha256: str) -> bool:
        return _validate_sha256(sha256) in self.manifest.members

    def list_members(self) -> List[ProjectMember]:
        with self._lock:
            return [ProjectMember.from_dict(d) for d in self.manifest.members.values()]

    # ---- overlay I/O ----
    def overlay_path(self, sha256: str) -> Path:
        sha256 = _validate_sha256(sha256)
        return self.overlay_dir / f"{sha256}.json.gz"

    def load_overlay(self, sha256: str) -> Dict[str, Any]:
        """Load the overlay for a member binary. Returns empty dict on miss."""
        path = self.overlay_path(sha256)
        data = _read_json(path, gzipped=True)
        if data is None:
            return {}
        if not isinstance(data, dict):
            logger.warning("Overlay %s is not a dict; ignoring", path)
            return {}
        return data

    def save_overlay(self, sha256: str, overlay: Dict[str, Any]) -> None:
        """Atomically save *overlay* for *sha256*. Tags with overlay version + meta."""
        sha256 = _validate_sha256(sha256)
        wrapper = dict(overlay)
        wrapper["_overlay_meta"] = {
            "version": OVERLAY_VERSION,
            "project_id": self.id,
            "binary_sha256": sha256,
            "saved_at": time.time(),
        }
        _atomic_write_json(self.overlay_path(sha256), wrapper, gzipped=True)

    def delete_overlay(self, sha256: str) -> None:
        sha256 = _validate_sha256(sha256)
        try:
            self.overlay_path(sha256).unlink(missing_ok=True)
        except OSError as e:
            logger.warning("Failed to delete overlay %s: %s", sha256[:12], e)

    # ---- manifest persistence ----
    def save_manifest(self) -> None:
        with self._lock:
            _atomic_write_json(self.manifest_path, self.manifest.to_dict())

    def touch_last_opened(self) -> None:
        with self._lock:
            self.manifest.last_opened = time.time()
        self.save_manifest()

    def set_last_active(self, sha256: str) -> None:
        sha256 = _validate_sha256(sha256)
        with self._lock:
            if sha256 not in self.manifest.members:
                raise ValueError(f"Binary {sha256[:12]} is not a member of this project")
            self.manifest.last_active_sha256 = sha256
        self.save_manifest()

    def set_primary(self, sha256: str) -> None:
        sha256 = _validate_sha256(sha256)
        with self._lock:
            if sha256 not in self.manifest.members:
                raise ValueError(f"Binary {sha256[:12]} is not a member of this project")
            self.manifest.primary_sha256 = sha256
        self.save_manifest()

    def add_tags(self, tags: List[str], replace: bool = False) -> List[str]:
        with self._lock:
            if replace:
                self.manifest.tags = list(dict.fromkeys(t.strip() for t in tags if t.strip()))
            else:
                existing = set(self.manifest.tags)
                for t in tags:
                    t = t.strip()
                    if t and t not in existing:
                        self.manifest.tags.append(t)
                        existing.add(t)
            result = list(self.manifest.tags)
        self.save_manifest()
        return result

    def remove_tags(self, tags: List[str]) -> List[str]:
        drop = {t.strip() for t in tags if t.strip()}
        with self._lock:
            self.manifest.tags = [t for t in self.manifest.tags if t not in drop]
            result = list(self.manifest.tags)
        self.save_manifest()
        return result

    def set_dashboard_state(self, key: str, value: Any) -> None:
        with self._lock:
            self.manifest.dashboard_state[key] = value
        self.save_manifest()

    def register_stub_member(self, member: ProjectMember,
                             make_primary: bool = True) -> None:
        """Add *member* to the project's manifest and (optionally) mark it as
        primary + last-active. Used by archive importers that have already
        synthesized a stub binary path inside ``binaries/`` and need to land
        the manifest entry under the project's lock without reaching into
        the private ``_lock`` attribute themselves.
        """
        with self._lock:
            self.manifest.members[member.sha256] = member.to_dict()
            if make_primary:
                self.manifest.primary_sha256 = member.sha256
                self.manifest.last_active_sha256 = member.sha256
        self.save_manifest()

    # ---- artifact storage helpers ----
    def member_present(self, sha256: str) -> bool:
        """True if the member's binary copy actually exists on disk.

        Migrated projects (and projects whose binary file was deleted from
        disk) may have a member entry without an actual file copy. The file
        is adopted lazily on the next ``open_file`` matching the sha256.
        """
        sha256 = _validate_sha256(sha256)
        with self._lock:
            d = self.manifest.members.get(sha256)
        if not d:
            return False
        cp = d.get("copy_path") or ""
        return bool(cp) and Path(cp).is_file()

    def snapshot_members(self) -> List[Dict[str, Any]]:
        """Return a stable snapshot of every member as a list of dicts.

        Public alternative to dashboard code reaching into ``project._lock``
        directly. The snapshot is a fresh list of fresh dicts, so callers
        can iterate without holding the lock and without risk of seeing a
        concurrent ``add_binary``/``remove_binary`` mutate the underlying
        manifest mid-iteration. Each dict carries the same fields the
        manifest stores: ``sha256``, ``filename``, ``size``, ``mode``,
        ``copy_path``, ``added_at`` (and ``mtime`` if present).
        """
        with self._lock:
            return [
                {
                    "sha256": sha,
                    "filename": d.get("original_filename") or "(unnamed)",
                    "size": int(d.get("size", 0) or 0),
                    "mode": d.get("mode", "unknown"),
                    "copy_path": d.get("copy_path") or "",
                    "added_at": float(d.get("added_at", 0.0) or 0.0),
                    "mtime": d.get("mtime"),
                }
                for sha, d in self.manifest.members.items()
            ]

    def snapshot_members_with_presence(self) -> Tuple[List[Dict[str, Any]], str, str]:
        """Snapshot members AND the primary/last_active sha256s under one lock.

        Returns ``(members, primary_sha256, last_active_sha256)``. Used by
        ``_project_card_detail`` so the dashboard's grid build can stat each
        ``copy_path`` outside the lock without paying the per-member
        ``member_present()`` round-trip-with-lock cost. Stat happens at the
        call site, not here, because we don't want to hold the lock during
        I/O.
        """
        with self._lock:
            members = [
                (sha, dict(d)) for sha, d in self.manifest.members.items()
            ]
            primary = self.manifest.primary_sha256 or ""
            last_active = self.manifest.last_active_sha256 or ""
        # Convert to the same shape as snapshot_members() for consistency.
        out = [
            {
                "sha256": sha,
                "filename": d.get("original_filename") or "(unnamed)",
                "size": int(d.get("size", 0) or 0),
                "mode": d.get("mode", "unknown"),
                "copy_path": d.get("copy_path") or "",
                "added_at": float(d.get("added_at", 0.0) or 0.0),
            }
            for sha, d in members
        ]
        return out, primary, last_active

    def adopt_binary_into_stub(self, sha256: str, source_path: str) -> ProjectMember:
        """Materialise a stub member (created by migration) by copying the
        binary into the project's binaries/ dir.

        The stub member's ``copy_path`` already points to the destination
        path inside the project — we just need to actually copy the file
        there. Hardlinks when same filesystem.
        """
        sha256 = _validate_sha256(sha256)
        with self._lock:
            d = self.manifest.members.get(sha256)
            if d is None:
                raise ValueError(f"No stub member for {sha256[:12]}")
            target = Path(d.get("copy_path") or "")
            if not target:
                raise ValueError(f"Member {sha256[:12]} has no copy_path")
            if not target.is_file():
                src = Path(source_path)
                if not src.is_file():
                    raise FileNotFoundError(f"Source binary not found: {source_path}")
                _hardlink_or_copy(src, target)
                d["size"] = target.stat().st_size
                d["added_at"] = time.time()
            self.save_manifest()
            return ProjectMember.from_dict(d)

    def adopt_artifact_file(self, source_path: str, sha256: str) -> Path:
        """Copy/link *source_path* into the project's artifacts/ dir. Returns new path.

        Filename is namespaced by sha256 prefix to prevent collisions across
        artifacts that share a basename.
        """
        src = Path(source_path)
        if not src.is_file():
            raise FileNotFoundError(f"Artifact source not found: {source_path}")
        sha256 = _validate_sha256(sha256)
        dest_name = f"{sha256[:12]}_{_safe_filename(src.name)}"
        dest = self.artifacts_dir / dest_name
        if dest.exists():
            return dest  # already adopted
        _hardlink_or_copy(src, dest)
        return dest

    def adopt_artifact_directory(self, source_path: str, sha256: str) -> Path:
        """Copy a directory tree into the project's artifacts/ dir.

        Uses ``shutil.copytree``; the caller is responsible for size/depth
        validation before invoking this.
        """
        src = Path(source_path)
        if not src.is_dir():
            raise NotADirectoryError(f"Artifact source not a directory: {source_path}")
        sha256 = _validate_sha256(sha256)
        dest_name = f"{sha256[:12]}_{_safe_filename(src.name)}"
        dest = self.artifacts_dir / dest_name
        if dest.exists():
            return dest
        self.artifacts_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copytree(src, dest, symlinks=False)
        return dest

    def __repr__(self) -> str:
        return f"<Project id={self.id} name={self.name!r} members={len(self.manifest.members)}>"


# ---------------------------------------------------------------------------
#  ScratchProject
# ---------------------------------------------------------------------------

class ScratchProject:
    """An in-memory project created on open_file when no real project is active.

    ScratchProjects have no on-disk presence. They are promoted to real
    Projects via ``ProjectManager.promote_scratch`` on the first state
    mutation that requires persistence.
    """

    def __init__(self):
        self.id = f"scratch-{uuid.uuid4().hex[:8]}"
        self.created_at = time.time()
        # Mirror Project's interface where it makes sense, but everything is
        # held in memory.
        self.members: Dict[str, ProjectMember] = {}
        self.primary_sha256: Optional[str] = None
        self.last_active_sha256: Optional[str] = None
        # Per-binary overlays — empty until promotion. ScratchProject is
        # designed to be discarded if nothing meaningful happens, so we
        # don't bother snapshotting state into here; promotion captures it
        # straight from AnalyzerState.

    @property
    def name(self) -> str:
        return f"(scratch {self.id[-8:]})"

    @property
    def is_scratch(self) -> bool:
        return True

    def add_member(self, sha256: str, original_filename: str, source_path: str,
                   size: int = 0, mode: str = "unknown") -> ProjectMember:
        sha256 = _validate_sha256(sha256)
        member = ProjectMember(
            sha256=sha256,
            original_filename=original_filename,
            copy_path=source_path,  # scratch refs original location until promoted
            added_at=time.time(),
            size=size,
            mode=mode,
        )
        self.members[sha256] = member
        if self.primary_sha256 is None:
            self.primary_sha256 = sha256
        self.last_active_sha256 = sha256
        return member

    def has_member(self, sha256: str) -> bool:
        try:
            return _validate_sha256(sha256) in self.members
        except ValueError:
            return False

    def __repr__(self) -> str:
        return f"<ScratchProject id={self.id} members={len(self.members)}>"


# ---------------------------------------------------------------------------
#  ProjectManager
# ---------------------------------------------------------------------------

class ProjectManager:
    """Singleton-style manager for all on-disk projects.

    Instantiated once at module import time as ``project_manager``. Thread-safe;
    a single re-entrant lock guards index and manifest mutations. Per-project
    overlay reads/writes are atomic via tempfile + os.replace.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._projects: Dict[str, Project] = {}  # in-memory cache
        self._migration_done = False
        self._ensure_dirs()
        self._load_index()
        # Lazy migration: only run if no projects exist yet (first launch
        # under the new code). Failures here must NEVER crash startup.
        try:
            self._migrate_legacy_cache_if_needed()
        except Exception as e:
            logger.warning("Project migration aborted: %s", e, exc_info=True)

    # ------------------------------------------------------------------
    #  Initialisation
    # ------------------------------------------------------------------
    def _ensure_dirs(self) -> None:
        try:
            PROJECTS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(str(PROJECTS_DIR), 0o700)
        except OSError as e:
            logger.warning("Failed to ensure projects dir: %s", e)

    def _load_index(self) -> None:
        """Load the project index. Missing index = empty (migration handled separately)."""
        index = _read_json(INDEX_FILE) or {}
        if not isinstance(index, dict):
            logger.warning("Projects index.json is not a dict; resetting")
            index = {}
        with self._lock:
            for pid, summary in index.items():
                if not isinstance(summary, dict):
                    continue
                root = PROJECTS_DIR / pid
                manifest_path = root / "manifest.json"
                manifest_data = _read_json(manifest_path)
                if manifest_data is None:
                    logger.warning("Project %s missing manifest; skipping", pid)
                    continue
                try:
                    manifest = ProjectManifest.from_dict(manifest_data)
                    self._projects[pid] = Project(manifest, root)
                except Exception as e:
                    logger.warning("Failed to load project %s: %s", pid, e)

    def _save_index(self) -> None:
        """Persist the index file. Caller must hold ``_lock``."""
        index = {}
        for pid, proj in self._projects.items():
            m = proj.manifest
            primary = m.members.get(m.primary_sha256 or "", {}) if m.primary_sha256 else {}
            index[pid] = {
                "name": m.name,
                "last_opened": m.last_opened,
                "created_at": m.created_at,
                "primary_sha256": m.primary_sha256,
                "primary_filename": primary.get("original_filename") if primary else None,
                "tags": list(m.tags),
                "member_count": len(m.members),
            }
        try:
            _atomic_write_json(INDEX_FILE, index)
        except OSError as e:
            logger.error("Failed to save projects index: %s", e)

    # ------------------------------------------------------------------
    #  Lookup
    # ------------------------------------------------------------------
    def get(self, project_id: str) -> Optional[Project]:
        with self._lock:
            return self._projects.get(project_id)

    def find_by_name(self, name: str) -> Optional[Project]:
        with self._lock:
            for p in self._projects.values():
                if p.manifest.name == name:
                    return p
        return None

    def resolve(self, id_or_name: str) -> Optional[Project]:
        """Resolve by ID first, then by name."""
        return self.get(id_or_name) or self.find_by_name(id_or_name)

    def list(self, *, filter: str = "", tag: Optional[str] = None,
             sort_by: str = "last_opened") -> List[Project]:
        with self._lock:
            projects = list(self._projects.values())
        if filter:
            f = filter.lower()
            projects = [
                p for p in projects
                if f in p.manifest.name.lower()
                or any(f in t.lower() for t in p.manifest.tags)
            ]
        if tag:
            projects = [p for p in projects if tag in p.manifest.tags]
        if sort_by == "name":
            projects.sort(key=lambda p: p.manifest.name.lower())
        elif sort_by == "created_at":
            projects.sort(key=lambda p: p.manifest.created_at, reverse=True)
        else:  # last_opened (default)
            projects.sort(key=lambda p: p.manifest.last_opened, reverse=True)
        return projects

    def lookup_by_sha(self, sha256: str) -> List[Project]:
        sha256 = _validate_sha256(sha256)
        with self._lock:
            return [p for p in self._projects.values() if sha256 in p.manifest.members]

    # ------------------------------------------------------------------
    #  Creation
    # ------------------------------------------------------------------
    def create(self, name: Optional[str] = None, *,
               name_locked: bool = False,
               tags: Optional[List[str]] = None) -> Project:
        """Create an empty project (no binaries yet). *name* may be None for auto-naming
        later via ``promote_scratch``."""
        with self._lock:
            if len(self._projects) >= MAX_PROJECTS:
                raise RuntimeError(
                    f"Project limit reached ({MAX_PROJECTS}). Delete old projects first."
                )
            if name is not None:
                name = _validate_project_name(name)
                if self.find_by_name(name):
                    raise ValueError(f"A project named {name!r} already exists")
            else:
                # placeholder; caller will rename via promote_scratch
                name = f"unnamed_{uuid.uuid4().hex[:6]}"

            pid = _new_project_id()
            while pid in self._projects:
                pid = _new_project_id()

            now = time.time()
            manifest = ProjectManifest(
                id=pid,
                name=name,
                name_locked=name_locked,
                created_at=now,
                last_opened=now,
                tags=list(dict.fromkeys((tags or []))),
            )
            root = PROJECTS_DIR / pid
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            (root / "binaries").mkdir(exist_ok=True, mode=0o700)
            (root / "artifacts").mkdir(exist_ok=True, mode=0o700)
            (root / "overlay").mkdir(exist_ok=True, mode=0o700)

            project = Project(manifest, root)
            project.save_manifest()
            self._projects[pid] = project
            self._save_index()
            logger.info("Project created: %s (%s)", name, pid)
            return project

    def add_binary(self, project: Project, source_path: str,
                   *, declared_sha256: Optional[str] = None,
                   declared_size: Optional[int] = None,
                   mode: str = "unknown") -> ProjectMember:
        """Add a binary to *project* by copying it into binaries/.

        Hashing happens here unless ``declared_sha256`` is supplied (in which
        case the caller has already computed it). The file is hardlinked when
        possible (same filesystem), else copied.
        """
        if project.is_scratch:
            raise TypeError("Cannot add binary to a scratch project — promote it first")
        src = Path(source_path)
        if not src.is_file():
            raise FileNotFoundError(f"Binary not found: {source_path}")

        if declared_sha256:
            sha256 = _validate_sha256(declared_sha256)
            size = declared_size if declared_size is not None else src.stat().st_size
        else:
            sha256, size = _hash_file(src)

        with project._lock:
            if len(project.manifest.members) >= MAX_BINARIES_PER_PROJECT and sha256 not in project.manifest.members:
                raise RuntimeError(
                    f"Project has reached the {MAX_BINARIES_PER_PROJECT}-binary limit"
                )
            existing = project.manifest.members.get(sha256)
            if existing:
                logger.debug("Binary %s already in project %s", sha256[:12], project.id)
                return ProjectMember.from_dict(existing)

            dest_name = f"{sha256[:16]}_{_safe_filename(src.name)}"
            dest = project.binaries_dir / dest_name
            if not dest.exists():
                _hardlink_or_copy(src, dest)

            member = ProjectMember(
                sha256=sha256,
                original_filename=src.name,
                copy_path=str(dest),
                added_at=time.time(),
                size=size,
                mode=mode,
            )
            project.manifest.members[sha256] = member.to_dict()
            if project.manifest.primary_sha256 is None:
                project.manifest.primary_sha256 = sha256
            project.manifest.last_active_sha256 = sha256
            project.save_manifest()

        with self._lock:
            self._save_index()
        return member

    def remove_binary(self, project: Project, sha256: str) -> None:
        sha256 = _validate_sha256(sha256)
        if project.is_scratch:
            raise TypeError("Cannot remove binary from a scratch project")
        with project._lock:
            if sha256 not in project.manifest.members:
                raise ValueError(f"Binary {sha256[:12]} is not a member of this project")
            if len(project.manifest.members) == 1:
                raise RuntimeError("Cannot remove the only binary in a project; delete the project instead")
            if project.manifest.primary_sha256 == sha256:
                raise RuntimeError(
                    f"Cannot remove primary binary {sha256[:12]}. "
                    "Set a different primary first via set_primary()."
                )
            member = ProjectMember.from_dict(project.manifest.members[sha256])
            try:
                Path(member.copy_path).unlink(missing_ok=True)
            except OSError as e:
                logger.warning("Failed to delete binary copy %s: %s", member.copy_path, e)
            project.delete_overlay(sha256)
            del project.manifest.members[sha256]
            if project.manifest.last_active_sha256 == sha256:
                project.manifest.last_active_sha256 = project.manifest.primary_sha256
            project.save_manifest()
        with self._lock:
            self._save_index()

    # ------------------------------------------------------------------
    #  Rename / tag / delete
    # ------------------------------------------------------------------
    def rename(self, project: Project, new_name: str) -> None:
        new_name = _validate_project_name(new_name)
        with self._lock:
            existing = self.find_by_name(new_name)
            if existing and existing.id != project.id:
                raise ValueError(f"A project named {new_name!r} already exists")
            project.manifest.name = new_name
            project.manifest.name_locked = True
            project.save_manifest()
            self._save_index()

    def delete(self, project: Project) -> None:
        if project.is_scratch:
            return
        with self._lock:
            self._projects.pop(project.id, None)
            self._save_index()
        try:
            shutil.rmtree(project.root)
        except OSError as e:
            logger.warning("Failed to delete project dir %s: %s", project.root, e)

    # ------------------------------------------------------------------
    #  Scratch promotion
    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    #  Migration: cache v1 → cache v2 + projects
    # ------------------------------------------------------------------
    def _migrate_legacy_cache_if_needed(self) -> None:
        """One-shot scan of ~/.arkana/cache/ for v1 wrappers carrying user state.

        For each entry with non-empty notes/artifacts/renames/types/triage:
          1. Create a project named ``{filename_stem}_{sha8}`` (or unique
             variant on collision), tagged ``migrated``.
          2. Add a stub member: copy_path is the *would-be* path inside
             binaries/, but the file is not copied (the original binary
             is no longer addressable from the cache wrapper alone).
             ``open_file`` later adopts the file via
             ``Project.adopt_binary_into_stub`` once the user re-opens it.
          3. Save the legacy state as the project's overlay for that sha256.
          4. Re-write the cache wrapper as v2 (strip user fields).

        Idempotent: if the projects index already has entries, this is a
        no-op (the user is already on the new world). Per-entry failures
        are logged and skipped.
        """
        with self._lock:
            if self._migration_done or self._projects:
                self._migration_done = True
                return

        # Avoid importing cache at module level — circular reference risk.
        try:
            from arkana.cache import CACHE_DIR, META_FILE, CACHE_FORMAT_VERSION
        except ImportError:
            return

        if not META_FILE.exists():
            self._migration_done = True
            return

        try:
            with open(META_FILE, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("Migration: cannot read cache meta: %s", e)
            return

        if not isinstance(meta, dict) or not meta:
            self._migration_done = True
            return

        migrated = 0
        skipped = 0
        for sha256, entry_meta in list(meta.items()):
            try:
                if not _SHA256_RE.match(sha256):
                    continue
                entry_path = CACHE_DIR / sha256[:2] / f"{sha256}.json.gz"
                if not entry_path.exists():
                    continue
                try:
                    with gzip.open(entry_path, "rt", encoding="utf-8") as f:
                        wrapper = json.load(f)
                except (OSError, gzip.BadGzipFile, json.JSONDecodeError) as e:
                    logger.warning("Migration: skipping unreadable entry %s: %s", sha256[:12], e)
                    continue
                cmeta = wrapper.get("_cache_meta") or {}
                version = cmeta.get("cache_format_version")
                if version is None or version >= CACHE_FORMAT_VERSION:
                    # Already v2; nothing to migrate.
                    continue
                if version != 1:
                    logger.warning(
                        "Migration: unknown cache version %s for %s; skipping",
                        version, sha256[:12],
                    )
                    continue

                notes = wrapper.get("notes") or []
                tool_history = wrapper.get("tool_history") or []
                artifacts = wrapper.get("artifacts") or []
                renames = wrapper.get("renames") or {}
                custom_types = wrapper.get("custom_types") or {}
                triage_status = wrapper.get("triage_status") or {}
                has_data = bool(
                    notes or tool_history or artifacts
                    or any(renames.get(k) for k in ("functions", "variables", "labels"))
                    or any(custom_types.get(k) for k in ("structs", "enums"))
                    or triage_status
                )

                if has_data:
                    original_filename = (
                        cmeta.get("original_filename")
                        or entry_meta.get("original_filename")
                        or "sample"
                    )
                    mode = cmeta.get("mode") or entry_meta.get("mode") or "unknown"
                    size = (
                        cmeta.get("original_file_size")
                        or entry_meta.get("file_size")
                        or 0
                    )
                    # Try the rich auto_name_sample helper first — uses
                    # whatever pe_data + triage live in the v1 wrapper.
                    rich_slug = ""
                    try:
                        from arkana.mcp.tools_workflow import _build_sample_slug
                        pe_data_legacy = wrapper.get("pe_data") or {}
                        triage_legacy = pe_data_legacy.get("_cached_triage") or {}
                        info = _build_sample_slug(
                            pe_data=pe_data_legacy,
                            triage=triage_legacy,
                            notes=notes,
                            file_size_fallback=int(size or 0) or None,
                        )
                        candidate = info.get("slug") or ""
                        # Skip the trivial sample_<sha8> fallback since we
                        # already include the sha8 suffix below.
                        if candidate and not candidate.startswith("sample_"):
                            rich_slug = re.sub(r"[^\w\-. ]", "_", candidate)[:80]
                    except Exception:
                        rich_slug = ""
                    if rich_slug:
                        base_name = f"{rich_slug}_{sha256[:8]}"
                    else:
                        stem = os.path.splitext(original_filename)[0] or "sample"
                        stem = re.sub(r"[^\w\-. ]", "_", stem)[:80]
                        base_name = f"{stem}_{sha256[:8]}"
                    name = base_name
                    counter = 2
                    while self.find_by_name(name):
                        name = f"{base_name}_{counter}"
                        counter += 1

                    project = self.create(name=name, name_locked=False, tags=["migrated"])

                    # Add stub member: deterministic copy_path inside binaries/.
                    stub_name = f"{sha256[:16]}_{_safe_filename(original_filename)}"
                    stub_path = project.binaries_dir / stub_name
                    project.binaries_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                    member = ProjectMember(
                        sha256=sha256,
                        original_filename=original_filename,
                        copy_path=str(stub_path),
                        added_at=time.time(),
                        size=int(size or 0),
                        mode=mode,
                    )
                    with project._lock:
                        project.manifest.members[sha256] = member.to_dict()
                        project.manifest.primary_sha256 = sha256
                        project.manifest.last_active_sha256 = sha256
                        project.save_manifest()

                    # Save the user state as the project's overlay
                    overlay = {
                        "notes": notes,
                        "tool_history": tool_history,
                        "artifacts": artifacts,
                        "renames": renames,
                        "custom_types": custom_types,
                        "triage_status": triage_status,
                    }
                    project.save_overlay(sha256, overlay)
                    migrated += 1
                else:
                    skipped += 1

                # Re-write cache wrapper as v2 (strip user fields).
                v2_wrapper = {
                    "_cache_meta": {**cmeta, "cache_format_version": CACHE_FORMAT_VERSION},
                    "pe_data": wrapper.get("pe_data") or {},
                }
                # Atomic rewrite
                tmp_fd = tempfile.NamedTemporaryFile(
                    dir=str(entry_path.parent), suffix=".tmp", delete=False,
                )
                tmp_path = Path(tmp_fd.name)
                try:
                    tmp_fd.close()
                    with gzip.open(tmp_path, "wt", encoding="utf-8") as gz:
                        json.dump(v2_wrapper, gz)
                    tmp_path.replace(entry_path)
                except Exception as e:
                    logger.warning("Migration: failed to rewrite v2 wrapper for %s: %s", sha256[:12], e)
                    tmp_path.unlink(missing_ok=True)
                    # Don't unwind the project — the overlay is still valid.

            except Exception as e:
                logger.warning("Migration: failed for %s: %s", sha256[:12], e, exc_info=True)
                continue

        with self._lock:
            self._save_index()
            self._migration_done = True

        if migrated or skipped:
            logger.info(
                "Cache migration complete: %d project(s) created, %d entry/entries upgraded without user data",
                migrated, skipped,
            )

    def promote_scratch(self, scratch: ScratchProject, *,
                        suggested_name: Optional[str] = None,
                        tags: Optional[List[str]] = None) -> Project:
        """Promote *scratch* to a real on-disk Project.

        Members are copied into binaries/ and the manifest is written. Caller
        is responsible for binding the new project to AnalyzerState and
        flushing the current overlay via ``Project.save_overlay``.

        *suggested_name* is used if provided; otherwise an unnamed placeholder
        is set and ``name_locked`` is False so the caller (or
        ``auto_name_sample`` integration) can rename later.
        """
        # Build initial name (validation may suffix on collision)
        if suggested_name:
            try:
                base_name = _validate_project_name(suggested_name)
            except ValueError:
                base_name = f"unnamed_{uuid.uuid4().hex[:6]}"
            with self._lock:
                if self.find_by_name(base_name):
                    # Auto-suffix with first sha8 of primary, or counter
                    primary = scratch.primary_sha256 or ""
                    suffix = primary[:8] if primary else uuid.uuid4().hex[:6]
                    candidate = f"{base_name}_{suffix}"
                    counter = 2
                    while self.find_by_name(candidate):
                        candidate = f"{base_name}_{suffix}_{counter}"
                        counter += 1
                    base_name = candidate
            project = self.create(name=base_name, name_locked=False, tags=tags)
        else:
            project = self.create(name=None, name_locked=False, tags=tags)

        # Copy members from scratch
        for sha256, member in scratch.members.items():
            try:
                self.add_binary(
                    project,
                    member.copy_path,
                    declared_sha256=sha256,
                    declared_size=member.size,
                    mode=member.mode,
                )
            except FileNotFoundError:
                logger.warning(
                    "Scratch member %s source path %s no longer exists; skipping during promotion",
                    sha256[:12], member.copy_path,
                )
                continue
            except Exception as e:
                logger.warning("Failed to add scratch member %s during promotion: %s", sha256[:12], e)

        # Restore primary/last_active selection from scratch
        with project._lock:
            if scratch.primary_sha256 and scratch.primary_sha256 in project.manifest.members:
                project.manifest.primary_sha256 = scratch.primary_sha256
            if scratch.last_active_sha256 and scratch.last_active_sha256 in project.manifest.members:
                project.manifest.last_active_sha256 = scratch.last_active_sha256
            project.save_manifest()

        with self._lock:
            self._save_index()

        logger.info("Scratch %s promoted to project %s (%s)", scratch.id, project.id, project.name)
        return project


# ---------------------------------------------------------------------------
#  Module-level singleton
# ---------------------------------------------------------------------------

# Lazy initialisation: created on first import. Tests that need a fresh
# state can call ``_reset_for_tests()``.
project_manager = ProjectManager()


def _reset_for_tests() -> None:
    """Re-instantiate the singleton (test-only)."""
    global project_manager
    project_manager = ProjectManager()
