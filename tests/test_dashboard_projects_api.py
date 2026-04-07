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


# ---------------------------------------------------------------------------
#  _locate_binary_for_stub (used by api_projects_open to recover migrated stubs)
# ---------------------------------------------------------------------------

class TestLocateBinaryForStub:
    """Verify the dashboard helper that finds a binary on disk by sha256
    when a project member's copy_path is missing (migrated stub case)."""

    def _hash(self, data: bytes) -> str:
        import hashlib
        return hashlib.sha256(data).hexdigest()

    def test_returns_empty_when_no_roots(self):
        from arkana.dashboard.app import _locate_binary_for_stub

        class S:
            allowed_paths = None
            samples_path = None

        assert _locate_binary_for_stub(S(), "a" * 64, "x.bin") == ""

    def test_returns_empty_for_blank_inputs(self, tmp_path):
        from arkana.dashboard.app import _locate_binary_for_stub

        class S:
            allowed_paths = [str(tmp_path)]
            samples_path = None

        assert _locate_binary_for_stub(S(), "", "x.bin") == ""
        assert _locate_binary_for_stub(S(), "a" * 64, "") == ""
        assert _locate_binary_for_stub(S(), "a" * 64, "/") == ""

    def test_finds_via_samples_path_root(self, tmp_path):
        """When allowed_paths is None (stdio mode), samples_path is the
        only hint — verify the helper still finds files there."""
        from arkana.dashboard.app import _locate_binary_for_stub
        data = b"hello arkana"
        f = tmp_path / "loader.exe"
        f.write_bytes(data)

        class S:
            allowed_paths = None
            samples_path = str(tmp_path)

        result = _locate_binary_for_stub(S(), self._hash(data), "loader.exe")
        assert result == str(f.resolve())

    def test_finds_in_subdirectory(self, tmp_path):
        from arkana.dashboard.app import _locate_binary_for_stub
        sub = tmp_path / "Protect" / "themida"
        sub.mkdir(parents=True)
        data = b"\xde\xad\xbe\xef" * 100
        f = sub / "sample.exe"
        f.write_bytes(data)

        class S:
            allowed_paths = None
            samples_path = str(tmp_path)

        assert _locate_binary_for_stub(S(), self._hash(data), "sample.exe") == str(f.resolve())

    def test_filename_match_but_different_content_rejected(self, tmp_path):
        """If a file has the right name but the wrong sha256, it must NOT
        be returned — the hash check is the source of truth."""
        from arkana.dashboard.app import _locate_binary_for_stub
        wrong = tmp_path / "sample.exe"
        wrong.write_bytes(b"wrong content")

        class S:
            allowed_paths = None
            samples_path = str(tmp_path)

        assert _locate_binary_for_stub(S(), "0" * 64, "sample.exe") == ""

    def test_finds_renamed_file_by_hash(self, tmp_path):
        """If the target filename doesn't exist but a content match does,
        the helper falls back to hashing the first few non-name files."""
        from arkana.dashboard.app import _locate_binary_for_stub
        data = b"renamed binary content"
        f = tmp_path / "different_name.exe"
        f.write_bytes(data)

        class S:
            allowed_paths = None
            samples_path = str(tmp_path)

        result = _locate_binary_for_stub(S(), self._hash(data), "original_name.exe")
        assert result == str(f.resolve())

    def test_allowed_paths_takes_precedence(self, tmp_path):
        """Path-sandboxed deployments rely on allowed_paths — verify those
        are searched in addition to samples_path."""
        from arkana.dashboard.app import _locate_binary_for_stub
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        data = b"abc123"
        f = a / "x.bin"
        f.write_bytes(data)

        class S:
            allowed_paths = [str(a)]
            samples_path = str(b)  # different dir

        assert _locate_binary_for_stub(S(), self._hash(data), "x.bin") == str(f.resolve())

    def test_export_dir_env_var_searched(self, tmp_path, monkeypatch):
        """Extracted artefacts often live in the export dir — verify the
        helper picks up ARKANA_EXPORT_DIR even when not in samples_path."""
        from arkana.dashboard.app import _locate_binary_for_stub
        export = tmp_path / "out"
        export.mkdir()
        data = b"extracted payload"
        f = export / "payload.bin"
        f.write_bytes(data)
        monkeypatch.setenv("ARKANA_EXPORT_DIR", str(export))

        class S:
            allowed_paths = None
            samples_path = None

        assert _locate_binary_for_stub(S(), self._hash(data), "payload.bin") == str(f.resolve())

    def test_skips_oversized_files(self, tmp_path, monkeypatch):
        """Files above the size cap should not be hashed (defends against
        accidentally hashing 10GB ISOs)."""
        from arkana.dashboard import app as app_mod
        from arkana.dashboard.app import _locate_binary_for_stub
        f = tmp_path / "huge.bin"
        f.write_bytes(b"x" * 1024)
        monkeypatch.setattr(app_mod, "_LOCATE_MAX_FILE_BYTES", 100)

        class S:
            allowed_paths = None
            samples_path = str(tmp_path)

        # Even though the filename matches, the size cap blocks hashing
        # so the helper returns "" rather than reading the file.
        assert _locate_binary_for_stub(S(), "0" * 64, "huge.bin") == ""

    def test_walked_cap_bounds_search(self, tmp_path, monkeypatch):
        """The walked-entry cap protects against pathological trees."""
        from arkana.dashboard import app as app_mod
        from arkana.dashboard.app import _locate_binary_for_stub
        # Tighten the cap and create a few files past it
        monkeypatch.setattr(app_mod, "_LOCATE_MAX_WALK", 3)
        for i in range(10):
            (tmp_path / f"f{i}.bin").write_bytes(b"x")

        class S:
            allowed_paths = None
            samples_path = str(tmp_path)

        # Search must terminate without raising even though entries > cap
        result = _locate_binary_for_stub(S(), "0" * 64, "missing.bin")
        assert result == ""


# ---------------------------------------------------------------------------
#  V2 archive importer safety (path traversal, size caps, member caps)
# ---------------------------------------------------------------------------

class TestImportProjectV2Safety:
    """Verify _import_project_v2 blocks malicious archive contents."""

    def _build_archive(self, path: str, members: list) -> None:
        """Build a tar.gz with the given (name, data, member_type) entries."""
        import io
        import tarfile
        with tarfile.open(path, "w:gz") as tar:
            for entry in members:
                name = entry["name"]
                data = entry.get("data", b"")
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                if entry.get("type") == "dir":
                    info.type = tarfile.DIRTYPE
                    info.size = 0
                tar.addfile(info, io.BytesIO(data))

    def test_path_traversal_blocked(self, manager, tmp_path):
        """A member with .. components escaping project/ must be rejected."""
        import json as _json
        from arkana.mcp.tools_export import _import_project_v2
        arch = tmp_path / "evil.tar.gz"
        self._build_archive(str(arch), [
            {"name": "manifest.json", "data": _json.dumps({"export_version": 2}).encode()},
            {"name": "project/foo/../../../etc/pwned", "data": b"bad"},
        ])
        with pytest.raises(RuntimeError, match="escapes project root|Unsafe archive"):
            _import_project_v2(str(arch), {"export_version": 2, "project_name": "evil"})

    def test_absolute_path_blocked(self, manager, tmp_path):
        import json as _json
        from arkana.mcp.tools_export import _import_project_v2
        arch = tmp_path / "abs.tar.gz"
        self._build_archive(str(arch), [
            {"name": "manifest.json", "data": _json.dumps({"export_version": 2}).encode()},
            {"name": "/etc/passwd", "data": b"root:x:0:0"},
        ])
        with pytest.raises(RuntimeError, match="absolute path"):
            _import_project_v2(str(arch), {"export_version": 2, "project_name": "abs"})

    def test_per_member_size_cap(self, manager, tmp_path, monkeypatch):
        """A single oversized member exceeding the per-file cap must be rejected."""
        import json as _json
        from arkana.mcp import tools_export
        from arkana.mcp.tools_export import _import_project_v2
        monkeypatch.setattr(tools_export, "_MAX_V2_MEMBER_BYTES", 32)  # 32 byte cap
        arch = tmp_path / "huge_member.tar.gz"
        self._build_archive(str(arch), [
            {"name": "manifest.json", "data": _json.dumps({"export_version": 2}).encode()},
            {"name": "project/manifest.json", "data": b"{}"},
            {"name": "project/big.bin", "data": b"x" * 1024},  # 1 KB > 32 B cap
        ])
        with pytest.raises(RuntimeError, match="per-file size cap"):
            _import_project_v2(str(arch), {"export_version": 2, "project_name": "huge"})

    def test_total_size_cap(self, manager, tmp_path, monkeypatch):
        """The cumulative member size cap must trigger before extraction completes."""
        import json as _json
        from arkana.mcp import tools_export
        from arkana.mcp.tools_export import _import_project_v2
        monkeypatch.setattr(tools_export, "_MAX_V2_ARCHIVE_BYTES", 256)  # 256 byte total
        arch = tmp_path / "total.tar.gz"
        members = [
            {"name": "manifest.json", "data": _json.dumps({"export_version": 2}).encode()},
            {"name": "project/manifest.json", "data": b"{}"},
        ]
        for i in range(20):
            members.append({"name": f"project/f{i}.bin", "data": b"x" * 64})
        self._build_archive(str(arch), members)
        with pytest.raises(RuntimeError, match="total size cap"):
            _import_project_v2(str(arch), {"export_version": 2, "project_name": "total"})

    def test_member_count_cap(self, manager, tmp_path, monkeypatch):
        """Too many members in a single archive must be rejected."""
        import json as _json
        from arkana.mcp import tools_export
        from arkana.mcp.tools_export import _import_project_v2
        monkeypatch.setattr(tools_export, "_MAX_V2_ARCHIVE_MEMBERS", 5)
        arch = tmp_path / "many.tar.gz"
        members = [
            {"name": "manifest.json", "data": _json.dumps({"export_version": 2}).encode()},
        ]
        for i in range(20):
            members.append({"name": f"project/f{i}.bin", "data": b"x"})
        self._build_archive(str(arch), members)
        with pytest.raises(RuntimeError, match="member cap"):
            _import_project_v2(str(arch), {"export_version": 2, "project_name": "many"})

    def test_symlink_member_blocked(self, manager, tmp_path):
        import io
        import json as _json
        import tarfile
        from arkana.mcp.tools_export import _import_project_v2
        arch = tmp_path / "symlink.tar.gz"
        with tarfile.open(str(arch), "w:gz") as tar:
            mf = _json.dumps({"export_version": 2}).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size = len(mf)
            tar.addfile(info, io.BytesIO(mf))
            sym = tarfile.TarInfo("project/payload")
            sym.type = tarfile.SYMTYPE
            sym.linkname = "/etc/passwd"
            tar.addfile(sym)
        with pytest.raises(RuntimeError, match="unsafe entry"):
            _import_project_v2(str(arch), {"export_version": 2, "project_name": "sym"})

    def test_partial_extract_cleaned_up(self, manager, tmp_path):
        """A failed extraction must remove the partial new_root directory."""
        import json as _json
        from arkana.mcp.tools_export import _import_project_v2
        from arkana.projects import PROJECTS_DIR
        before = set(PROJECTS_DIR.iterdir()) if PROJECTS_DIR.exists() else set()
        arch = tmp_path / "fail.tar.gz"
        self._build_archive(str(arch), [
            {"name": "manifest.json", "data": _json.dumps({"export_version": 2}).encode()},
            {"name": "project/foo/../../../etc/x", "data": b"bad"},
        ])
        with pytest.raises(RuntimeError):
            _import_project_v2(str(arch), {"export_version": 2, "project_name": "fail"})
        after = set(PROJECTS_DIR.iterdir()) if PROJECTS_DIR.exists() else set()
        # No new project directory should remain on disk
        assert after == before


# ---------------------------------------------------------------------------
#  PROJECT_NAME_RE — ASCII-only enforcement (security: confusable names)
# ---------------------------------------------------------------------------

class TestProjectNameRegex:
    """The project name regex must reject unicode confusables that allowed
    visual spoofing across find_by_name dedup."""

    def test_ascii_alpha_accepted(self):
        from arkana.constants import PROJECT_NAME_RE
        assert PROJECT_NAME_RE.match("my_project")
        assert PROJECT_NAME_RE.match("ProjectFoo-1.2")
        assert PROJECT_NAME_RE.match("a b c")

    def test_unicode_word_chars_rejected(self):
        """Cyrillic 'а' (U+0430) is visually identical to ASCII 'a' but
        previously matched ``\\w``."""
        from arkana.constants import PROJECT_NAME_RE
        assert PROJECT_NAME_RE.match("foo\u0430") is None  # cyrillic a
        assert PROJECT_NAME_RE.match("project\u202e") is None  # RTL override
        assert PROJECT_NAME_RE.match("\uff21\uff22") is None  # fullwidth A B

    def test_path_separators_rejected(self):
        from arkana.constants import PROJECT_NAME_RE
        assert PROJECT_NAME_RE.match("foo/bar") is None
        assert PROJECT_NAME_RE.match("foo\\bar") is None
        assert PROJECT_NAME_RE.match("foo:bar") is None

    def test_length_cap(self):
        from arkana.constants import PROJECT_NAME_RE
        assert PROJECT_NAME_RE.match("a" * 100)
        assert PROJECT_NAME_RE.match("a" * 101) is None
