"""Unit tests for arkana/projects.py — ProjectManager, Project, ScratchProject,
overlay round-trip, lazy promotion, name validation, and v1→v2 cache migration.
"""
from __future__ import annotations

import gzip
import json
import os
import time
from pathlib import Path

import pytest

from arkana.state import AnalyzerState, set_current_state


# ---------------------------------------------------------------------------
#  Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def projects_dir(tmp_path, monkeypatch):
    """Redirect ~/.arkana/projects to a tmp dir."""
    pdir = tmp_path / "projects"
    monkeypatch.setattr("arkana.projects.PROJECTS_DIR", pdir)
    monkeypatch.setattr("arkana.projects.INDEX_FILE", pdir / "index.json")
    monkeypatch.setattr("arkana.constants.PROJECTS_DIR", pdir)
    return pdir


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    """Redirect ~/.arkana/cache to a tmp dir."""
    cdir = tmp_path / "cache"
    cdir.mkdir(parents=True)
    monkeypatch.setattr("arkana.cache.CACHE_DIR", cdir)
    monkeypatch.setattr("arkana.cache.META_FILE", cdir / "meta.json")
    return cdir


@pytest.fixture
def manager(projects_dir):
    """Fresh ProjectManager instance in an isolated dir."""
    from arkana.projects import ProjectManager
    return ProjectManager()


@pytest.fixture
def clean_state():
    s = AnalyzerState()
    set_current_state(s)
    yield s
    try:
        set_current_state(None)
    except Exception:
        pass


@pytest.fixture
def sample_binary(tmp_path):
    """Write a small binary to disk and return (path, sha256)."""
    import hashlib
    p = tmp_path / "sample.bin"
    data = b"MZ" + b"\x00" * 64
    p.write_bytes(data)
    return str(p), hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
#  ProjectManager CRUD
# ---------------------------------------------------------------------------

class TestProjectManagerCRUD:
    def test_empty_manager(self, manager):
        assert manager.list() == []

    def test_create_with_name(self, manager):
        p = manager.create("test_project")
        assert p.name == "test_project"
        assert p.id
        assert manager.find_by_name("test_project") is p
        assert manager.get(p.id) is p

    def test_create_without_name_uses_placeholder(self, manager):
        p = manager.create(None)
        assert p.name.startswith("unnamed_")

    def test_create_duplicate_name_rejected(self, manager):
        manager.create("dup")
        with pytest.raises(ValueError, match="already exists"):
            manager.create("dup")

    def test_create_invalid_name_rejected(self, manager):
        with pytest.raises(ValueError):
            manager.create("/etc/passwd")
        with pytest.raises(ValueError):
            manager.create("")
        with pytest.raises(ValueError):
            manager.create("a" * 200)

    def test_rename_collision_rejected(self, manager):
        a = manager.create("a")
        manager.create("b")
        with pytest.raises(ValueError):
            manager.rename(a, "b")

    def test_rename_sets_locked(self, manager):
        p = manager.create("a", name_locked=False)
        manager.rename(p, "renamed")
        assert p.manifest.name == "renamed"
        assert p.manifest.name_locked is True

    def test_delete(self, manager):
        p = manager.create("ephemeral")
        pid = p.id
        manager.delete(p)
        assert manager.get(pid) is None
        assert not p.root.exists()

    def test_list_filtering(self, manager):
        manager.create("alpha", tags=["red"])
        manager.create("beta", tags=["red", "blue"])
        manager.create("gamma", tags=["blue"])
        red = manager.list(tag="red")
        assert {p.name for p in red} == {"alpha", "beta"}
        b_only = manager.list(filter="bet")
        assert [p.name for p in b_only] == ["beta"]

    def test_index_round_trip(self, manager, projects_dir):
        manager.create("persistent", tags=["x"])
        # Re-instantiate to force index reload
        from arkana.projects import ProjectManager
        m2 = ProjectManager()
        assert m2.find_by_name("persistent") is not None


# ---------------------------------------------------------------------------
#  Binary management
# ---------------------------------------------------------------------------

class TestBinaryManagement:
    def test_add_binary_copies_into_project(self, manager, sample_binary):
        path, sha = sample_binary
        p = manager.create("withbin")
        member = manager.add_binary(p, path)
        assert member.sha256 == sha
        assert Path(member.copy_path).is_file()
        assert p.manifest.primary_sha256 == sha
        assert p.manifest.last_active_sha256 == sha
        assert p.has_member(sha)
        assert p.member_present(sha)

    def test_add_binary_idempotent(self, manager, sample_binary):
        path, sha = sample_binary
        p = manager.create("withbin")
        m1 = manager.add_binary(p, path)
        m2 = manager.add_binary(p, path)
        assert m1.sha256 == m2.sha256
        assert len(p.manifest.members) == 1

    def test_remove_primary_rejected(self, manager, sample_binary, tmp_path):
        path, sha = sample_binary
        # Need a second binary to enable removing the first
        path2 = tmp_path / "second.bin"
        path2.write_bytes(b"second" + b"\x00" * 30)
        p = manager.create("multi")
        manager.add_binary(p, path)  # primary
        manager.add_binary(p, str(path2))
        with pytest.raises(RuntimeError, match="primary"):
            manager.remove_binary(p, sha)

    def test_remove_only_binary_rejected(self, manager, sample_binary):
        path, sha = sample_binary
        p = manager.create("solo")
        manager.add_binary(p, path)
        with pytest.raises(RuntimeError, match="only binary"):
            manager.remove_binary(p, sha)

    def test_lookup_by_sha(self, manager, sample_binary):
        path, sha = sample_binary
        p1 = manager.create("p1")
        manager.add_binary(p1, path)
        p2 = manager.create("p2")
        # Same binary, different project
        manager.add_binary(p2, path)
        results = manager.lookup_by_sha(sha)
        assert {p.id for p in results} == {p1.id, p2.id}


# ---------------------------------------------------------------------------
#  Overlay round-trip
# ---------------------------------------------------------------------------

class TestOverlayRoundTrip:
    def test_save_and_load_overlay(self, manager, sample_binary):
        path, sha = sample_binary
        p = manager.create("overlay_test")
        manager.add_binary(p, path)
        overlay = {
            "notes": [{"id": "n_1", "content": "hello"}],
            "tool_history": [{"tool_name": "open_file"}],
            "artifacts": [],
            "renames": {"functions": {"0x1000": "main"}, "variables": {}, "labels": {}},
            "custom_types": {"structs": {}, "enums": {}},
            "triage_status": {"0x1000": "suspicious"},
            "_cached_coverage": None,
            "_sandbox_report": None,
        }
        p.save_overlay(sha, overlay)
        loaded = p.load_overlay(sha)
        assert loaded["notes"][0]["content"] == "hello"
        assert loaded["renames"]["functions"]["0x1000"] == "main"
        assert loaded["triage_status"]["0x1000"] == "suspicious"
        assert loaded["_overlay_meta"]["binary_sha256"] == sha

    def test_apply_overlay_round_trip_through_state(self, manager, sample_binary, clean_state):
        path, sha = sample_binary
        p = manager.create("state_rt")
        manager.add_binary(p, path)
        clean_state.bind_project(p)
        # Mutate state
        clean_state.add_note("hello", category="general")
        clean_state.rename_function("0xdead", "unmangled")
        clean_state.set_triage_status("0xdead", "suspicious")
        # Snapshot and save
        snap = clean_state.snapshot_overlay()
        assert snap["notes"][0]["content"] == "hello"
        assert snap["renames"]["functions"]["0xdead"] == "unmangled"
        # Apply to a fresh state
        s2 = AnalyzerState()
        s2.apply_overlay(snap)
        assert any(n["content"] == "hello" for n in s2.get_notes())
        assert s2.renames["functions"]["0xdead"] == "unmangled"
        assert s2.triage_status["0xdead"] == "suspicious"


# ---------------------------------------------------------------------------
#  Lazy promotion
# ---------------------------------------------------------------------------

class TestLazyPromotion:
    def test_scratch_project_creation(self, manager, sample_binary):
        from arkana.projects import ScratchProject
        s = ScratchProject()
        path, sha = sample_binary
        s.add_member(sha, "sample.bin", path)
        assert s.is_scratch
        assert s.primary_sha256 == sha

    def test_promote_scratch_to_real(self, manager, sample_binary):
        from arkana.projects import ScratchProject
        s = ScratchProject()
        path, sha = sample_binary
        s.add_member(sha, "sample.bin", path, size=66)
        real = manager.promote_scratch(s, suggested_name="my_investigation")
        assert not real.is_scratch
        assert real.name == "my_investigation"
        assert real.has_member(sha)
        assert real.member_present(sha)

    def test_note_promotes_scratch_via_state(self, manager, sample_binary,
                                              clean_state, monkeypatch):
        # Patch the project_manager singleton to point at our isolated one
        monkeypatch.setattr("arkana.projects.project_manager", manager)
        from arkana.projects import ScratchProject
        s = ScratchProject()
        path, sha = sample_binary
        s.add_member(sha, "sample.bin", path, size=66)
        clean_state.bind_project(s)
        # Adding a note should promote
        clean_state.add_note("first finding", category="general")
        active = clean_state.get_active_project()
        assert active is not None
        assert not active.is_scratch
        assert active.has_member(sha)
        # Overlay was flushed; loading it back should give us the note
        overlay = active.load_overlay(sha)
        assert any(n["content"] == "first finding" for n in overlay["notes"])

    def test_artifact_registration_promotes_scratch(self, manager, sample_binary,
                                                     clean_state, monkeypatch):
        monkeypatch.setattr("arkana.projects.project_manager", manager)
        from arkana.projects import ScratchProject
        s = ScratchProject()
        path, sha = sample_binary
        s.add_member(sha, "sample.bin", path, size=66)
        clean_state.bind_project(s)
        clean_state.register_artifact(
            path="/tmp/some.bin", sha256="ab" * 32, md5="cd" * 16,
            size=10, source_tool="test", description="test artifact",
        )
        active = clean_state.get_active_project()
        assert not active.is_scratch


# ---------------------------------------------------------------------------
#  Same-binary in two projects
# ---------------------------------------------------------------------------

class TestProjectIsolation:
    def test_overlays_are_independent(self, manager, sample_binary):
        path, sha = sample_binary
        p1 = manager.create("inv1")
        p2 = manager.create("inv2")
        manager.add_binary(p1, path)
        manager.add_binary(p2, path)
        p1.save_overlay(sha, {"notes": [{"id": "n_1", "content": "p1 note"}]})
        p2.save_overlay(sha, {"notes": [{"id": "n_2", "content": "p2 note"}]})
        assert p1.load_overlay(sha)["notes"][0]["content"] == "p1 note"
        assert p2.load_overlay(sha)["notes"][0]["content"] == "p2 note"


# ---------------------------------------------------------------------------
#  Migration: cache v1 → v2 + projects
# ---------------------------------------------------------------------------

class TestMigration:
    def test_v1_with_user_data_creates_project(self, projects_dir, cache_dir, monkeypatch):
        # Build a v1 wrapper with user data
        sha = "ab" * 32
        wrapper = {
            "_cache_meta": {
                "cache_format_version": 1,
                "arkana_version": "test",
                "sha256": sha,
                "original_filename": "stealc.exe",
                "mode": "pe",
            },
            "pe_data": {"mode": "pe", "file_hashes": {"sha256": sha}},
            "notes": [{"id": "n_1", "content": "carved C2"}],
            "tool_history": [],
            "artifacts": [],
            "renames": {"functions": {"0x1000": "decrypt_config"}, "variables": {}, "labels": {}},
            "custom_types": {"structs": {}, "enums": {}},
            "triage_status": {},
        }
        entry_dir = cache_dir / sha[:2]
        entry_dir.mkdir(parents=True)
        with gzip.open(entry_dir / f"{sha}.json.gz", "wt", encoding="utf-8") as f:
            json.dump(wrapper, f)
        # Write a meta.json so the migration finds the entry
        meta_file = cache_dir / "meta.json"
        with open(meta_file, "w") as f:
            json.dump({sha: {"original_filename": "stealc.exe", "mode": "pe"}}, f)

        from arkana.projects import ProjectManager
        manager = ProjectManager()
        projects = manager.list()
        assert len(projects) == 1
        proj = projects[0]
        assert "stealc" in proj.name
        assert "migrated" in proj.manifest.tags
        assert sha in proj.manifest.members
        # The overlay should carry the migrated user data
        overlay = proj.load_overlay(sha)
        assert overlay["notes"][0]["content"] == "carved C2"
        assert overlay["renames"]["functions"]["0x1000"] == "decrypt_config"
        # The cache wrapper should have been re-written as v2
        with gzip.open(entry_dir / f"{sha}.json.gz", "rt", encoding="utf-8") as f:
            new_wrapper = json.load(f)
        assert new_wrapper["_cache_meta"]["cache_format_version"] == 2
        assert "notes" not in new_wrapper

    def test_v1_without_user_data_skipped(self, projects_dir, cache_dir):
        sha = "cd" * 32
        wrapper = {
            "_cache_meta": {
                "cache_format_version": 1,
                "arkana_version": "test",
                "sha256": sha,
                "original_filename": "clean.exe",
                "mode": "pe",
            },
            "pe_data": {"mode": "pe"},
            "notes": [],
            "tool_history": [],
            "artifacts": [],
            "renames": {"functions": {}, "variables": {}, "labels": {}},
            "custom_types": {"structs": {}, "enums": {}},
            "triage_status": {},
        }
        entry_dir = cache_dir / sha[:2]
        entry_dir.mkdir(parents=True)
        with gzip.open(entry_dir / f"{sha}.json.gz", "wt", encoding="utf-8") as f:
            json.dump(wrapper, f)
        meta_file = cache_dir / "meta.json"
        with open(meta_file, "w") as f:
            json.dump({sha: {"original_filename": "clean.exe", "mode": "pe"}}, f)

        from arkana.projects import ProjectManager
        manager = ProjectManager()
        # No project should be created for clean entries
        assert manager.list() == []
        # But the wrapper should still have been upgraded to v2
        with gzip.open(entry_dir / f"{sha}.json.gz", "rt", encoding="utf-8") as f:
            new_wrapper = json.load(f)
        assert new_wrapper["_cache_meta"]["cache_format_version"] == 2
