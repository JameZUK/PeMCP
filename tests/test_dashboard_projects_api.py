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

    def test_member_copy_paths_rewritten_into_new_project(
        self, manager, tmp_path
    ):
        """A v2 archive carries copy_path strings from the *source* project
        (e.g. ``/.../projects/{old_id}/binaries/x.exe``). After import, every
        member's copy_path must point inside the *new* project's binaries
        dir, otherwise filepath displays and adopt_binary_into_stub will
        cross-pollute or fail when the source project is later deleted.
        """
        import json as _json
        from arkana.mcp.tools_export import _import_project_v2

        # Build an archive that mimics what _export_project_v2 would produce:
        #   manifest.json (top wrapper)
        #   project/manifest.json (per-project, members[].copy_path under
        #                          a different project root)
        #   project/binaries/{name}  (the actual binary bytes)
        old_root = "/app/home/.arkana/projects/aaaaaaaaaaaaaaaa"
        binary_name = "deadbeef_sample.exe"
        binary_bytes = b"MZ" + b"\x00" * 510
        import hashlib as _h
        sha = _h.sha256(binary_bytes).hexdigest()
        proj_manifest = {
            "id": "aaaaaaaaaaaaaaaa",
            "name": "src_proj",
            "name_locked": False,
            "created_at": 1.0,
            "last_opened": 1.0,
            "primary_sha256": sha,
            "last_active_sha256": sha,
            "tags": [],
            "members": {
                sha: {
                    "sha256": sha,
                    "original_filename": "sample.exe",
                    "copy_path": f"{old_root}/binaries/{binary_name}",
                    "added_at": 1.0,
                    "size": len(binary_bytes),
                    "mode": "pe",
                }
            },
            "manifest_version": 1,
        }
        arch = tmp_path / "src_proj.tar.gz"
        self._build_archive(str(arch), [
            {"name": "manifest.json",
             "data": _json.dumps({"export_version": 2,
                                  "project_name": "src_proj"}).encode()},
            {"name": "project/manifest.json",
             "data": _json.dumps(proj_manifest).encode()},
            {"name": f"project/binaries/{binary_name}",
             "data": binary_bytes},
        ])
        result = _import_project_v2(
            str(arch),
            {"export_version": 2, "project_name": "src_proj"},
        )
        new_id = result["project_id"]
        proj = manager.get(new_id)
        assert proj is not None
        member = proj.get_member(sha)
        assert member is not None
        # The rewritten copy_path MUST live under the new project's
        # binaries dir, NOT the source project's old root.
        new_copy_path = Path(member.copy_path).resolve()
        new_binaries_dir = (proj.root / "binaries").resolve()
        assert new_copy_path.parent == new_binaries_dir, (
            f"copy_path {member.copy_path} did not get rewritten into the "
            f"new project's binaries dir {new_binaries_dir}"
        )
        # And the file at the rewritten path must be the actual binary.
        assert new_copy_path.is_file()
        assert new_copy_path.read_bytes() == binary_bytes


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


# ---------------------------------------------------------------------------
#  Dashboard executor shutdown handling (regression test)
# ---------------------------------------------------------------------------

class TestDashboardExecutorShutdown:
    """The dashboard daemon thread can outlive the MCP main thread by
    several seconds during interpreter shutdown. Previously the executor
    was registered with atexit and would be shut down mid-flight, causing
    every htmx poll to dump a traceback with ``RuntimeError: cannot
    schedule new futures after shutdown``. This class pins the fix:

      1. The atexit registration is gone (verified by attribute check).
      2. ``DashboardShutdownError`` exists and is raised by ``_dash_to_thread``
         when the executor is in the shutdown state.
      3. ``_api_error_response`` translates that error into a 503 instead of
         a 500 traceback.
    """

    def test_no_atexit_registration(self):
        """The executor should NOT be in the atexit handler chain — leaving
        it registered creates the half-shutdown window the bug exploits."""
        import atexit
        from arkana.dashboard import app
        # We can't trivially introspect atexit's registered callbacks across
        # Python versions, but we CAN sanity-check that the module no longer
        # imports atexit. This guards against re-introduction.
        import inspect
        src = inspect.getsource(app)
        # Allow the word in comments but not as a top-level import.
        assert "\nimport atexit" not in src, (
            "import atexit was reintroduced into dashboard/app.py — the "
            "atexit-registered shutdown caused production bug 2026-04-07"
        )

    def test_dashboard_shutdown_error_exists(self):
        from arkana.dashboard.app import DashboardShutdownError
        assert issubclass(DashboardShutdownError, RuntimeError)

    def test_dash_to_thread_translates_runtime_error(self):
        """When the executor is shut down, ``_dash_to_thread`` should raise
        DashboardShutdownError instead of leaking a generic RuntimeError."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from arkana.dashboard import app as app_mod
        from arkana.dashboard.app import _dash_to_thread, DashboardShutdownError

        # Swap in a fresh executor that we can shut down without
        # affecting the real dashboard executor used by other tests.
        old_executor = app_mod._dashboard_executor
        try:
            tmp_executor = ThreadPoolExecutor(max_workers=1)
            tmp_executor.shutdown(wait=True)
            app_mod._dashboard_executor = tmp_executor

            async def _run():
                with pytest.raises(DashboardShutdownError):
                    await _dash_to_thread(lambda: 42)

            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(_run())
            finally:
                loop.close()
        finally:
            app_mod._dashboard_executor = old_executor

    def test_api_error_response_returns_503_for_shutdown_error(self):
        from arkana.dashboard.app import _api_error_response, DashboardShutdownError
        resp = _api_error_response("test_endpoint", DashboardShutdownError("x"))
        assert resp.status_code == 503

    def test_api_error_response_still_returns_500_for_other_errors(self):
        from arkana.dashboard.app import _api_error_response
        resp = _api_error_response("test_endpoint", ValueError("x"))
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
#  Locate cache rehash on hit (defends against cached-then-replaced binary)
# ---------------------------------------------------------------------------

class TestLocateCacheRehash:
    """``_locate_cache_get`` re-hashes the cached path on every hit so a
    file replaced (with different content) at the cached path within the
    TTL window is not silently served. Critical: the previous version
    only checked path existence, leaking the wrong binary for a sha256."""

    def _hash(self, data: bytes) -> str:
        import hashlib
        return hashlib.sha256(data).hexdigest()

    def setup_method(self):
        # Reset the module-level cache between tests so cross-test
        # contamination can't mask a failure.
        from arkana.dashboard import app as app_mod
        with app_mod._locate_cache_lock:
            app_mod._locate_cache.clear()

    def test_cache_hit_returns_path_when_content_unchanged(self, tmp_path):
        from arkana.dashboard.app import _locate_cache_put, _locate_cache_get
        f = tmp_path / "x.bin"
        data = b"hello arkana"
        f.write_bytes(data)
        sha = self._hash(data)
        _locate_cache_put(sha, str(f))
        assert _locate_cache_get(sha) == str(f)

    def test_cache_hit_evicted_when_content_replaced(self, tmp_path):
        from arkana.dashboard.app import _locate_cache_put, _locate_cache_get
        f = tmp_path / "x.bin"
        original = b"original content"
        f.write_bytes(original)
        sha_original = self._hash(original)
        _locate_cache_put(sha_original, str(f))
        # Replace the file with different content at the same path.
        f.write_bytes(b"replaced content")
        # Cache hit must NOT return the path — content drift is detected.
        assert _locate_cache_get(sha_original) is None

    def test_cache_hit_evicted_when_path_deleted(self, tmp_path):
        from arkana.dashboard.app import _locate_cache_put, _locate_cache_get
        f = tmp_path / "x.bin"
        f.write_bytes(b"data")
        sha = self._hash(b"data")
        _locate_cache_put(sha, str(f))
        f.unlink()
        assert _locate_cache_get(sha) is None

    def test_cache_hit_evicted_after_ttl(self, tmp_path, monkeypatch):
        from arkana.dashboard import app as app_mod
        from arkana.dashboard.app import _locate_cache_put, _locate_cache_get
        f = tmp_path / "x.bin"
        data = b"ttl test"
        f.write_bytes(data)
        sha = self._hash(data)
        # Tighten TTL to a value we can race past.
        monkeypatch.setattr(app_mod, "_LOCATE_CACHE_TTL_S", 0.05)
        _locate_cache_put(sha, str(f))
        import time as _t
        _t.sleep(0.1)
        assert _locate_cache_get(sha) is None


# ---------------------------------------------------------------------------
#  _build_directory_tarball TOCTOU defence
# ---------------------------------------------------------------------------

class TestBuildDirectoryTarballTOCTOU:
    """The directory tarball helper opens the source dir with O_NOFOLLOW
    and walks via dir_fd, so a swap of the leaf or any parent symlink
    cannot redirect the archive contents."""

    def test_leaf_symlink_rejected(self, tmp_path):
        from arkana.dashboard.app import _build_directory_tarball
        target = tmp_path / "real"
        target.mkdir()
        (target / "secret.txt").write_text("ok")
        link = tmp_path / "link"
        link.symlink_to(target)
        with pytest.raises(RuntimeError, match="symlinked directory"):
            _build_directory_tarball(str(link), "bundle")

    def test_nonexistent_path_rejected(self, tmp_path):
        from arkana.dashboard.app import _build_directory_tarball
        with pytest.raises(RuntimeError, match="no longer exists"):
            _build_directory_tarball(str(tmp_path / "missing"), "bundle")

    def test_file_path_rejected(self, tmp_path):
        from arkana.dashboard.app import _build_directory_tarball
        f = tmp_path / "not-a-dir.txt"
        f.write_text("x")
        with pytest.raises(RuntimeError, match="not a directory"):
            _build_directory_tarball(str(f), "bundle")

    def test_real_directory_succeeds_and_skips_inner_symlinks(self, tmp_path):
        from arkana.dashboard.app import _build_directory_tarball, _unlink_quiet
        import tarfile
        src = tmp_path / "real_dir"
        src.mkdir()
        (src / "a.txt").write_text("alpha")
        (src / "b.txt").write_text("bravo")
        # Inner symlink to /etc/passwd — must NOT end up in the archive.
        (src / "evil_link").symlink_to("/etc/passwd")
        out_path = _build_directory_tarball(str(src), "bundle")
        try:
            with tarfile.open(out_path, "r:gz") as tf:
                names = tf.getnames()
            assert any(n.endswith("a.txt") for n in names)
            assert any(n.endswith("b.txt") for n in names)
            assert not any("evil_link" in n for n in names)
            assert not any("passwd" in n for n in names)
        finally:
            _unlink_quiet(out_path)


# ---------------------------------------------------------------------------
#  Project comparison endpoint bounds
# ---------------------------------------------------------------------------

class TestProjectComparisonBounds:
    """The PROJECTS sub-tab on the Similarity page can be triggered by any
    authenticated user against arbitrary project pairs. The cap and budget
    machinery must protect the dashboard executor from being pinned by a
    huge pair grid or a hostile binary pair."""

    def test_threshold_nan_clamps_to_default(self, manager, clean_state):
        from arkana.dashboard.state_api import get_project_comparison_data
        manager.create("alpha")
        manager.create("beta")
        a = next(p.id for p in manager.list() if p.name == "alpha")
        b = next(p.id for p in manager.list() if p.name == "beta")
        result = get_project_comparison_data(a, b, threshold=float("nan"))
        assert result["available"] is True
        assert result["threshold"] == 0.7

    def test_threshold_inf_clamps_to_default(self, manager, clean_state):
        from arkana.dashboard.state_api import get_project_comparison_data
        manager.create("alpha")
        manager.create("beta")
        a = next(p.id for p in manager.list() if p.name == "alpha")
        b = next(p.id for p in manager.list() if p.name == "beta")
        result = get_project_comparison_data(a, b, threshold=float("inf"))
        assert result["threshold"] == 0.7

    def test_threshold_negative_clamps_to_zero(self, manager, clean_state):
        from arkana.dashboard.state_api import get_project_comparison_data
        manager.create("alpha")
        manager.create("beta")
        a = next(p.id for p in manager.list() if p.name == "alpha")
        b = next(p.id for p in manager.list() if p.name == "beta")
        result = get_project_comparison_data(a, b, threshold=-5.0)
        assert result["threshold"] == 0.0

    def test_threshold_above_one_clamps_to_one(self, manager, clean_state):
        from arkana.dashboard.state_api import get_project_comparison_data
        manager.create("alpha")
        manager.create("beta")
        a = next(p.id for p in manager.list() if p.name == "alpha")
        b = next(p.id for p in manager.list() if p.name == "beta")
        result = get_project_comparison_data(a, b, threshold=99.0)
        assert result["threshold"] == 1.0

    def test_threshold_string_with_whitespace_parsed(self, manager, clean_state):
        from arkana.dashboard.state_api import get_project_comparison_data
        manager.create("alpha")
        manager.create("beta")
        a = next(p.id for p in manager.list() if p.name == "alpha")
        b = next(p.id for p in manager.list() if p.name == "beta")
        result = get_project_comparison_data(a, b, threshold="  0.5  ")
        assert result["threshold"] == 0.5

    def test_threshold_garbage_string_falls_back(self, manager, clean_state):
        from arkana.dashboard.state_api import get_project_comparison_data
        manager.create("alpha")
        manager.create("beta")
        a = next(p.id for p in manager.list() if p.name == "alpha")
        b = next(p.id for p in manager.list() if p.name == "beta")
        result = get_project_comparison_data(a, b, threshold="not a number")
        assert result["threshold"] == 0.7

    def test_self_compare_rejected(self, manager, clean_state):
        from arkana.dashboard.state_api import get_project_comparison_data
        manager.create("alpha")
        a = next(p.id for p in manager.list() if p.name == "alpha")
        result = get_project_comparison_data(a, a)
        assert result["available"] is False
        assert "different" in result["error"]

    def test_pair_grid_cap_refused(self, manager, clean_state, tmp_path,
                                   monkeypatch):
        """Two projects whose pair-grid product exceeds the cap should be
        refused outright with the actual size in the error."""
        from arkana.dashboard import state_api
        monkeypatch.setattr(state_api, "MAX_PROJECT_COMPARE_PAIRS", 4)

        # Build two projects with 3 stub members each → 9 pairs > cap of 4.
        from arkana.projects import ProjectMember
        proj_a = manager.create("compare_a")
        proj_b = manager.create("compare_b")
        for i, project in enumerate((proj_a, proj_b)):
            for j in range(3):
                sha = f"{i}{j}{'a' * 62}"[:64]
                stub_path = project.binaries_dir / f"stub_{sha[:8]}.bin"
                project.binaries_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                project.register_stub_member(
                    ProjectMember(
                        sha256=sha,
                        original_filename=f"stub_{j}.bin",
                        copy_path=str(stub_path),
                        added_at=0.0,
                        size=0,
                    ),
                    make_primary=(j == 0),
                )

        result = state_api.get_project_comparison_data(proj_a.id, proj_b.id)
        assert result["available"] is False
        assert "exceeds the dashboard cap" in result["error"]
        assert result["pair_count"] == 9
        assert result["max_pair_count"] == 4


# ---------------------------------------------------------------------------
#  Project.snapshot_members + register_stub_member
# ---------------------------------------------------------------------------

class TestProjectSnapshotMembers:
    """The public snapshot helpers replace the previous reach-into-private-
    `_lock` pattern across the dashboard layer. Verify they return stable
    snapshots and don't expose mutable references back into the manifest."""

    def _make_member(self, project, sha_prefix="a"):
        from arkana.projects import ProjectMember
        sha = (sha_prefix * 64)[:64]
        stub_path = project.binaries_dir / f"stub_{sha[:8]}.bin"
        project.binaries_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        return ProjectMember(
            sha256=sha,
            original_filename=f"stub_{sha[:8]}.bin",
            copy_path=str(stub_path),
            added_at=1234.0,
            size=42,
            mode="pe",
        )

    def test_snapshot_returns_list_of_dicts(self, manager, clean_state):
        proj = manager.create("snap")
        proj.register_stub_member(self._make_member(proj, "a"))
        members = proj.snapshot_members()
        assert isinstance(members, list)
        assert len(members) == 1
        m = members[0]
        assert m["sha256"].startswith("a")
        assert m["filename"].startswith("stub_")
        assert m["copy_path"].endswith(".bin")
        assert m["mode"] == "pe"

    def test_snapshot_does_not_alias_internal_state(self, manager, clean_state):
        proj = manager.create("snap")
        proj.register_stub_member(self._make_member(proj, "b"))
        members = proj.snapshot_members()
        members[0]["filename"] = "MUTATED"
        # The internal manifest should be untouched.
        again = proj.snapshot_members()
        assert again[0]["filename"] != "MUTATED"

    def test_snapshot_with_presence(self, manager, clean_state):
        proj = manager.create("snap")
        proj.register_stub_member(self._make_member(proj, "c"))
        members, primary, last_active = proj.snapshot_members_with_presence()
        assert len(members) == 1
        assert primary == ("c" * 64)[:64]
        assert last_active == ("c" * 64)[:64]

    def test_register_stub_member_rejects_external_path(self, manager,
                                                        clean_state, tmp_path):
        """``register_stub_member`` MUST refuse a copy_path outside the
        project's binaries/ directory — defends against future callers
        passing arbitrary paths into the manifest."""
        from arkana.projects import ProjectMember
        proj = manager.create("snap")
        bad_member = ProjectMember(
            sha256="d" * 64,
            original_filename="external.bin",
            copy_path=str(tmp_path / "outside.bin"),
            added_at=0.0,
            size=0,
        )
        with pytest.raises(ValueError, match="binaries/"):
            proj.register_stub_member(bad_member)

    def test_register_stub_member_accepts_internal_path(self, manager,
                                                        clean_state):
        proj = manager.create("snap")
        proj.register_stub_member(self._make_member(proj, "e"))
        assert len(proj.snapshot_members()) == 1


# ---------------------------------------------------------------------------
#  Bulk artifact batch helpers
# ---------------------------------------------------------------------------

class TestBulkArtifactBatch:
    """Bulk artifact ops were rewritten to single-pass O(L+N) under one
    lock acquisition. Pin the new behaviour."""

    def test_delete_batch_removes_only_matching_ids(self, clean_state):
        from arkana.state import set_current_state
        st = clean_state
        set_current_state(st)
        st.register_artifact(
            path="/tmp/a", sha256="a" * 64, md5="a" * 32, size=1,
            source_tool="test", description="a",
        )
        st.register_artifact(
            path="/tmp/b", sha256="b" * 64, md5="b" * 32, size=1,
            source_tool="test", description="b",
        )
        st.register_artifact(
            path="/tmp/c", sha256="c" * 64, md5="c" * 32, size=1,
            source_tool="test", description="c",
        )
        snap = st.get_all_artifacts_snapshot()
        assert len(snap) == 3
        ids = [snap[0]["id"], snap[2]["id"]]
        results = st.delete_artifacts_batch(ids)
        assert results[ids[0]] is True
        assert results[ids[1]] is True
        remaining = st.get_all_artifacts_snapshot()
        assert len(remaining) == 1
        assert remaining[0]["id"] == snap[1]["id"]

    def test_delete_batch_unknown_ids_return_false(self, clean_state):
        from arkana.state import set_current_state
        st = clean_state
        set_current_state(st)
        st.register_artifact(
            path="/tmp/a", sha256="a" * 64, md5="a" * 32, size=1,
            source_tool="test", description="a",
        )
        results = st.delete_artifacts_batch(["does_not_exist", "also_no"])
        assert results == {"does_not_exist": False, "also_no": False}
        assert len(st.get_all_artifacts_snapshot()) == 1

    def test_update_metadata_batch_applies_to_listed_ids(self, clean_state):
        from arkana.state import set_current_state
        st = clean_state
        set_current_state(st)
        st.register_artifact(
            path="/tmp/a", sha256="a" * 64, md5="a" * 32, size=1,
            source_tool="test", description="a",
        )
        st.register_artifact(
            path="/tmp/b", sha256="b" * 64, md5="b" * 32, size=1,
            source_tool="test", description="b",
        )
        ids = [a["id"] for a in st.get_all_artifacts_snapshot()]
        results = st.update_artifacts_metadata_batch(
            ids, tags=["malware", "loader"], replace_tags=True,
        )
        assert all(v is not None for v in results.values())
        for a in st.get_all_artifacts_snapshot():
            assert "malware" in a["tags"]
            assert "loader" in a["tags"]

    def test_update_metadata_batch_with_no_changes_returns_none(self, clean_state):
        from arkana.state import set_current_state
        st = clean_state
        set_current_state(st)
        st.register_artifact(
            path="/tmp/a", sha256="a" * 64, md5="a" * 32, size=1,
            source_tool="test", description="a",
        )
        ids = [a["id"] for a in st.get_all_artifacts_snapshot()]
        # No description / tags / notes given → all-None patch.
        results = st.update_artifacts_metadata_batch(ids)
        assert all(v is None for v in results.values())


# ---------------------------------------------------------------------------
#  Project membership cache invalidation
# ---------------------------------------------------------------------------

class TestProjectMembershipCache:
    """The cache short-circuits the O(P*M) walk for ~10s, but must
    invalidate when the projects index file changes (create/rename/delete)
    so freshly-created projects appear immediately in the BSim panel."""

    def setup_method(self):
        from arkana.dashboard import state_api
        with state_api._project_membership_lock:
            state_api._project_membership_cache["expires"] = 0.0
            state_api._project_membership_cache["index_mtime"] = None
            state_api._project_membership_cache["map"] = {}
            state_api._project_membership_cache["rebuilding"] = False

    def test_cache_invalidates_on_new_project(self, manager, clean_state):
        from arkana.dashboard.state_api import _project_membership_for_shas
        # Initial state: no projects.
        assert _project_membership_for_shas([("a" * 64)]) == {("a" * 64): []}
        # Create a project containing that sha.
        proj = manager.create("invalidation")
        from arkana.projects import ProjectMember
        sha = "a" * 64
        stub = proj.binaries_dir / "x.bin"
        proj.binaries_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        proj.register_stub_member(
            ProjectMember(
                sha256=sha,
                original_filename="x.bin",
                copy_path=str(stub),
                added_at=0.0,
                size=0,
            ),
        )
        # The membership cache must reflect the new project on the next
        # call (mtime invalidation, not the 10s TTL).
        result = _project_membership_for_shas([sha])
        assert len(result[sha]) == 1
        assert result[sha][0]["name"] == "invalidation"

    def test_cache_seed_with_no_index_file(self, manager, clean_state):
        """Empty-projects start state should not freeze the cache forever."""
        from arkana.dashboard.state_api import _project_membership_for_shas
        # Seed call with no projects.
        result = _project_membership_for_shas([("z" * 64)])
        assert result == {("z" * 64): []}
        # Add a project; should appear on the next call.
        proj = manager.create("seed_test")
        from arkana.projects import ProjectMember
        proj.binaries_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        proj.register_stub_member(
            ProjectMember(
                sha256="z" * 64,
                original_filename="z.bin",
                copy_path=str(proj.binaries_dir / "z.bin"),
                added_at=0.0,
                size=0,
            ),
        )
        result = _project_membership_for_shas([("z" * 64)])
        assert len(result["z" * 64]) == 1


# ---------------------------------------------------------------------------
#  Cache-hit fast_load deferred-promote (perf fix)
# ---------------------------------------------------------------------------

class TestPeFastLoadDeferredPromote:
    """Cache-hit ``open_file`` builds ``pe_object`` with ``fast_load=True``
    (headers + sections only) and sets ``_pe_object_needs_full_load=True``
    on state. ``_check_pe_object(require_headers=True)`` lazy-promotes via
    ``pe_object.full_load()`` on the first call that actually needs the
    directories. Without this, every cache hit paid the 10-15s full-parse
    cost up front."""

    def test_state_default_flag_is_false(self, clean_state):
        assert clean_state._pe_object_needs_full_load is False

    def test_close_pe_resets_flag(self, clean_state):
        clean_state._pe_object_needs_full_load = True
        clean_state.close_pe()
        assert clean_state._pe_object_needs_full_load is False

    def test_check_pe_object_promotes_lazily(self, clean_state, monkeypatch):
        """When the flag is set, _check_pe_object should call full_load()
        and clear the flag, even if full_load() raises (best-effort)."""
        from arkana.mcp import server as mcp_server
        promote_calls = []

        class FakePE:
            OPTIONAL_HEADER = object()  # truthy
            FILE_HEADER = object()
            def full_load(self):
                promote_calls.append(True)

        clean_state.pe_object = FakePE()
        clean_state._pe_object_needs_full_load = True
        clean_state.pe_data = {"file_hashes": {"sha256": "x" * 64}}
        clean_state.filepath = "/x"
        # Patch state inside the mcp.server module (it imports state directly)
        monkeypatch.setattr(mcp_server, "state", clean_state)
        mcp_server._check_pe_object("test_tool", require_headers=True)
        assert promote_calls == [True]
        assert clean_state._pe_object_needs_full_load is False

    def test_check_pe_object_skips_promote_when_flag_unset(self, clean_state,
                                                            monkeypatch):
        from arkana.mcp import server as mcp_server
        promote_calls = []

        class FakePE:
            OPTIONAL_HEADER = object()
            FILE_HEADER = object()
            def full_load(self):
                promote_calls.append(True)

        clean_state.pe_object = FakePE()
        clean_state._pe_object_needs_full_load = False
        clean_state.pe_data = {"file_hashes": {"sha256": "y" * 64}}
        clean_state.filepath = "/y"
        monkeypatch.setattr(mcp_server, "state", clean_state)
        mcp_server._check_pe_object("test_tool", require_headers=True)
        assert promote_calls == []

    def test_check_pe_object_swallows_full_load_exception(self, clean_state,
                                                           monkeypatch):
        """If pefile.full_load() raises (corrupt directory), the helper
        should log and clear the flag — NOT propagate the exception, so
        tools that don't strictly need the directory still work."""
        from arkana.mcp import server as mcp_server

        class FakePE:
            OPTIONAL_HEADER = object()
            FILE_HEADER = object()
            def full_load(self):
                raise RuntimeError("simulated corrupt directory")

        clean_state.pe_object = FakePE()
        clean_state._pe_object_needs_full_load = True
        clean_state.pe_data = {"file_hashes": {"sha256": "z" * 64}}
        clean_state.filepath = "/z"
        monkeypatch.setattr(mcp_server, "state", clean_state)
        # Should not raise — best-effort.
        mcp_server._check_pe_object("test_tool", require_headers=True)
        assert clean_state._pe_object_needs_full_load is False
