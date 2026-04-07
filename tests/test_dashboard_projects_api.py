"""Unit tests for arkana/dashboard/projects_api.py and artifacts_api.py."""
from __future__ import annotations

import os
import tempfile
import gzip
import json
from pathlib import Path

import pytest

from arkana.state import AnalyzerState, set_current_state


# ---------------------------------------------------------------------------
#  Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def projects_dir(tmp_path, monkeypatch):
    pdir = tmp_path / "projects"
    monkeypatch.setattr("arkana.projects.PROJECTS_DIR", pdir)
    monkeypatch.setattr("arkana.projects.INDEX_FILE", pdir / "index.json")
    monkeypatch.setattr("arkana.constants.PROJECTS_DIR", pdir)
    return pdir


@pytest.fixture
def manager(projects_dir):
    from arkana.projects import ProjectManager
    import arkana.projects as proj_mod
    import arkana.dashboard.projects_api as dash_mod
    pm = ProjectManager()
    # Patch both module-level bindings — projects_api captured the singleton
    # at import time via `from arkana.projects import project_manager`.
    original_proj = proj_mod.project_manager
    original_dash = dash_mod.project_manager
    proj_mod.project_manager = pm
    dash_mod.project_manager = pm
    yield pm
    proj_mod.project_manager = original_proj
    dash_mod.project_manager = original_dash


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
    import hashlib
    p = tmp_path / "sample.bin"
    data = b"MZ" + b"\x00" * 64
    p.write_bytes(data)
    return str(p), hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
#  projects_api: list / detail / active / create / rename / tag / delete
# ---------------------------------------------------------------------------

class TestProjectsApiBasics:
    def test_empty_list(self, manager, clean_state):
        from arkana.dashboard.projects_api import get_projects_list_data
        data = get_projects_list_data()
        assert data["projects"] == []
        assert data["total_count"] == 0
        assert data["active_project_id"] is None
        assert data["active_scratch"] is False

    def test_list_after_create(self, manager, clean_state):
        from arkana.dashboard.projects_api import get_projects_list_data, create_project_data
        create_project_data("alpha", tags=["red"])
        create_project_data("beta", tags=["red", "blue"])
        data = get_projects_list_data()
        assert len(data["projects"]) == 2
        assert {p["name"] for p in data["projects"]} == {"alpha", "beta"}

    def test_filter_by_tag(self, manager, clean_state):
        from arkana.dashboard.projects_api import get_projects_list_data, create_project_data
        create_project_data("alpha", tags=["red"])
        create_project_data("beta", tags=["blue"])
        data = get_projects_list_data(tag="red")
        assert [p["name"] for p in data["projects"]] == ["alpha"]

    def test_filter_by_text(self, manager, clean_state):
        from arkana.dashboard.projects_api import get_projects_list_data, create_project_data
        create_project_data("stealc_investigation")
        create_project_data("emotet_dropper")
        data = get_projects_list_data(filter="steal")
        assert len(data["projects"]) == 1
        assert data["projects"][0]["name"] == "stealc_investigation"

    def test_create_invalid_name_returns_error(self, manager, clean_state):
        from arkana.dashboard.projects_api import create_project_data
        with pytest.raises(ValueError):
            create_project_data("/etc/passwd")

    def test_create_duplicate_returns_error(self, manager, clean_state):
        from arkana.dashboard.projects_api import create_project_data
        create_project_data("dup")
        with pytest.raises(ValueError):
            create_project_data("dup")

    def test_rename(self, manager, clean_state):
        from arkana.dashboard.projects_api import create_project_data, rename_project_data
        resp = create_project_data("original_name")
        pid = resp["project"]["id"]
        result = rename_project_data(pid, "renamed_name")
        assert result["status"] == "success"
        assert result["project"]["name"] == "renamed_name"
        assert result["project"]["name_locked"] is True

    def test_rename_unknown_project(self, manager, clean_state):
        from arkana.dashboard.projects_api import rename_project_data
        result = rename_project_data("nonexistent_id", "new_name")
        assert "error" in result

    def test_tag_add_and_remove(self, manager, clean_state):
        from arkana.dashboard.projects_api import create_project_data, tag_project_data
        resp = create_project_data("tagged")
        pid = resp["project"]["id"]
        tag_project_data(pid, add=["malware", "stealer"])
        tag_project_data(pid, remove=["malware"])
        from arkana.dashboard.projects_api import get_project_detail_data
        proj = get_project_detail_data(pid)
        assert proj["tags"] == ["stealer"]

    def test_tag_replace(self, manager, clean_state):
        from arkana.dashboard.projects_api import create_project_data, tag_project_data, get_project_detail_data
        resp = create_project_data("retagged", tags=["old1", "old2"])
        pid = resp["project"]["id"]
        tag_project_data(pid, add=["fresh"], replace=True)
        proj = get_project_detail_data(pid)
        assert proj["tags"] == ["fresh"]

    def test_delete(self, manager, clean_state):
        from arkana.dashboard.projects_api import create_project_data, delete_project_data, get_project_detail_data
        resp = create_project_data("ephemeral")
        pid = resp["project"]["id"]
        result = delete_project_data(pid)
        assert result["status"] == "success"
        assert get_project_detail_data(pid) is None


class TestProjectsApiActive:
    def test_active_when_none(self, manager, clean_state):
        from arkana.dashboard.projects_api import get_active_project_data
        data = get_active_project_data()
        assert data["active"] is False
        assert data["project"] is None

    def test_active_with_real_project(self, manager, clean_state):
        from arkana.dashboard.projects_api import get_active_project_data
        from arkana.projects import project_manager
        proj = project_manager.create("active_test")
        clean_state.bind_project(proj)
        data = get_active_project_data()
        assert data["active"] is True
        assert data["scratch"] is False
        assert data["project"]["name"] == "active_test"

    def test_active_with_scratch(self, manager, clean_state):
        from arkana.dashboard.projects_api import get_active_project_data
        from arkana.projects import ScratchProject
        s = ScratchProject()
        clean_state.bind_project(s)
        data = get_active_project_data()
        assert data["active"] is True
        assert data["scratch"] is True
        assert data["project"]["id"].startswith("scratch-")


class TestProjectsApiDashboardState:
    def test_save_dashboard_state_whitelist(self, manager, clean_state):
        from arkana.dashboard.projects_api import create_project_data, save_dashboard_state, get_project_detail_data
        resp = create_project_data("dash_state_test")
        pid = resp["project"]["id"]
        # Allowed key
        ok = save_dashboard_state(pid, "last_tab", "functions")
        assert ok["status"] == "success"
        # Disallowed key rejected
        bad = save_dashboard_state(pid, "arbitrary_key", "x")
        assert "error" in bad

    def test_dashboard_state_appears_in_card(self, manager, clean_state):
        from arkana.dashboard.projects_api import create_project_data, save_dashboard_state, get_project_detail_data
        resp = create_project_data("dash_state_card")
        pid = resp["project"]["id"]
        save_dashboard_state(pid, "last_tab", "hexview")
        card = get_project_detail_data(pid)
        assert card["last_tab"] == "hexview"


# ---------------------------------------------------------------------------
#  artifacts_api
# ---------------------------------------------------------------------------

class TestArtifactsApi:
    def _make_artifacts(self, state):
        state.register_artifact(
            path="/tmp/a.bin", sha256="aa" * 32, md5="11" * 16,
            size=100, source_tool="refinery", description="payload A",
            detected_type="PE", tags=["malware"],
        )
        state.register_artifact(
            path="/tmp/b.bin", sha256="bb" * 32, md5="22" * 16,
            size=200, source_tool="crypto", description="decrypted blob",
            detected_type="binary", tags=["decrypted"],
        )
        state.register_artifact(
            path="/tmp/c_dir", sha256="cc" * 32, md5="33" * 16,
            size=500, source_tool="refinery_dotnet",
            description="extracted resources", detected_type="directory",
            kind="directory",
            members=[
                {"relative": "x.bin", "size": 100, "sha256": "x" * 64},
                {"relative": "y.bin", "size": 400, "sha256": "y" * 64},
            ],
        )

    def test_list_empty(self, clean_state):
        from arkana.dashboard.artifacts_api import get_artifacts_list_data
        data = get_artifacts_list_data()
        assert data["artifacts"] == []
        assert data["total_count"] == 0

    def test_list_with_artifacts(self, clean_state):
        from arkana.dashboard.artifacts_api import get_artifacts_list_data
        self._make_artifacts(clean_state)
        data = get_artifacts_list_data()
        assert data["filtered_count"] == 3
        assert data["facets"]["kinds"]
        names = {a["name"] for a in data["artifacts"]}
        assert "a.bin" in names
        assert "b.bin" in names
        assert "c_dir" in names

    def test_filter_by_kind(self, clean_state):
        from arkana.dashboard.artifacts_api import get_artifacts_list_data
        self._make_artifacts(clean_state)
        data = get_artifacts_list_data(kind="directory")
        assert data["filtered_count"] == 1
        assert data["artifacts"][0]["kind"] == "directory"

    def test_filter_by_tool(self, clean_state):
        from arkana.dashboard.artifacts_api import get_artifacts_list_data
        self._make_artifacts(clean_state)
        data = get_artifacts_list_data(source_tool="refinery")
        assert data["filtered_count"] == 1
        assert data["artifacts"][0]["source_tool"] == "refinery"

    def test_filter_by_tag(self, clean_state):
        from arkana.dashboard.artifacts_api import get_artifacts_list_data
        self._make_artifacts(clean_state)
        data = get_artifacts_list_data(tag="malware")
        assert data["filtered_count"] == 1

    def test_filter_by_text(self, clean_state):
        from arkana.dashboard.artifacts_api import get_artifacts_list_data
        self._make_artifacts(clean_state)
        data = get_artifacts_list_data(filter="decrypted")
        assert data["filtered_count"] == 1

    def test_facets(self, clean_state):
        from arkana.dashboard.artifacts_api import get_artifacts_list_data
        self._make_artifacts(clean_state)
        data = get_artifacts_list_data()
        kind_counts = {f["name"]: f["count"] for f in data["facets"]["kinds"]}
        assert kind_counts == {"file": 2, "directory": 1}
        tool_counts = {f["name"]: f["count"] for f in data["facets"]["tools"]}
        assert tool_counts["refinery"] == 1
        assert tool_counts["crypto"] == 1

    def test_get_detail(self, clean_state):
        from arkana.dashboard.artifacts_api import get_artifact_detail
        self._make_artifacts(clean_state)
        artifacts = clean_state.get_all_artifacts_snapshot()
        target_id = next(a["id"] for a in artifacts if a["kind"] == "directory")
        detail = get_artifact_detail(target_id)
        assert detail is not None
        assert detail["kind"] == "directory"
        assert "members" in detail
        assert len(detail["members"]) == 2

    def test_update_metadata(self, clean_state):
        from arkana.dashboard.artifacts_api import update_artifact_metadata_data
        self._make_artifacts(clean_state)
        target_id = clean_state.get_all_artifacts_snapshot()[0]["id"]
        result = update_artifact_metadata_data(
            target_id, description="new desc", tags=["edited"], replace_tags=True,
        )
        assert result["status"] == "success"
        assert result["artifact"]["description"] == "new desc"
        assert "edited" in result["artifact"]["tags"]

    def test_delete_single(self, clean_state):
        from arkana.dashboard.artifacts_api import delete_artifact_data
        self._make_artifacts(clean_state)
        target_id = clean_state.get_all_artifacts_snapshot()[0]["id"]
        result = delete_artifact_data(target_id)
        assert result["status"] == "success"
        assert len(clean_state.get_all_artifacts_snapshot()) == 2

    def test_delete_unknown(self, clean_state):
        from arkana.dashboard.artifacts_api import delete_artifact_data
        result = delete_artifact_data("art_does_not_exist")
        assert "error" in result

    def test_bulk_delete(self, clean_state):
        from arkana.dashboard.artifacts_api import bulk_delete_artifacts
        self._make_artifacts(clean_state)
        all_ids = [a["id"] for a in clean_state.get_all_artifacts_snapshot()]
        result = bulk_delete_artifacts(all_ids[:2])
        assert result["deleted_count"] == 2
        assert len(clean_state.get_all_artifacts_snapshot()) == 1

    def test_bulk_tag(self, clean_state):
        from arkana.dashboard.artifacts_api import bulk_tag_artifacts
        self._make_artifacts(clean_state)
        all_ids = [a["id"] for a in clean_state.get_all_artifacts_snapshot()]
        result = bulk_tag_artifacts(all_ids, ["bulk_tagged"], replace_tags=False)
        assert result["updated_count"] == 3
        for art in clean_state.get_all_artifacts_snapshot():
            assert "bulk_tagged" in (art.get("tags") or [])


# ---------------------------------------------------------------------------
#  Importable archives scanner
# ---------------------------------------------------------------------------

class TestImportableArchives:
    """list_importable_archives scans multiple candidate directories
    (env var dirs, project source-tree output/, /output). The tests below
    point ARKANA_EXPORT_DIR at a fresh tmp dir and assert the test's
    archives appear, without asserting an exact count (since real archives
    in the source tree's output/ also get returned)."""

    def test_does_not_crash_on_empty_env_dir(self, manager, clean_state, tmp_path, monkeypatch):
        monkeypatch.setenv("ARKANA_EXPORT_DIR", str(tmp_path))
        from arkana.dashboard.projects_api import list_importable_archives
        data = list_importable_archives()
        # Whatever the count is, the structure must be valid
        assert "count" in data
        assert "archives" in data
        assert data["count"] == len(data["archives"])

    def test_finds_test_archives(self, manager, clean_state, tmp_path, monkeypatch):
        monkeypatch.setenv("ARKANA_EXPORT_DIR", str(tmp_path))
        (tmp_path / "stealc_a1b2c3d4.arkana_project.tar.gz").write_bytes(b"fake")
        (tmp_path / "emotet_xyz.pemcp_project.tar.gz").write_bytes(b"fake")
        (tmp_path / "not_an_archive.txt").write_bytes(b"x")
        from arkana.dashboard.projects_api import list_importable_archives
        data = list_importable_archives()
        names = {a["name"] for a in data["archives"]}
        assert "stealc_a1b2c3d4.arkana_project.tar.gz" in names
        assert "emotet_xyz.pemcp_project.tar.gz" in names
        assert "not_an_archive.txt" not in names
