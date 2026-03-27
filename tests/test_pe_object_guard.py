"""Tests for _check_pe_object guard — ensures tools don't crash when pe_object is None.

Covers Bug #1 (pe_object None crashes) and Bug #2 (exports type safety).
"""
import asyncio
import pytest
from unittest.mock import MagicMock

from arkana.state import AnalyzerState, set_current_state
from arkana.mcp.server import _check_pe_object


def _run(coro):
    return asyncio.run(coro)


class MockContext:
    def __init__(self):
        self.infos = []
        self.warnings = []
        self.errors = []

    async def info(self, msg):
        self.infos.append(msg)

    async def warning(self, msg):
        self.warnings.append(msg)

    async def error(self, msg):
        self.errors.append(msg)

    async def report_progress(self, current, total):
        pass


@pytest.fixture(autouse=True)
def clean_state():
    s = AnalyzerState()
    set_current_state(s)
    yield s
    set_current_state(None)


@pytest.fixture
def ctx():
    return MockContext()


def _make_pe_state(state, *, pe_object=None):
    """Set up state with pe_data loaded but configurable pe_object."""
    state.filepath = "/tmp/test.exe"
    state.pe_data = {
        "file_hashes": {"md5": "d41d8cd98f00b204e9800998ecf8427e", "sha256": "abc123"},
        "pe_header": {"machine_type": "IMAGE_FILE_MACHINE_AMD64", "entry_point": "0x1000"},
        "sections": [],
        "imports": {},
        "exports": {},
        "strings": [],
    }
    state.pe_object = pe_object
    state._binary_data = b"MZ" + b"\x00" * 100


# ─── _check_pe_object unit tests ─────────────────────────────────────

class TestCheckPeObject:
    def test_raises_when_pe_object_is_none(self, clean_state):
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object is not available"):
            _check_pe_object("test_tool")

    def test_passes_with_real_pe_object(self, clean_state):
        mock_pe = MagicMock()
        mock_pe.OPTIONAL_HEADER = MagicMock()
        mock_pe.__data__ = b"\x00" * 100
        _make_pe_state(clean_state, pe_object=mock_pe)
        # Should not raise
        _check_pe_object("test_tool")

    def test_require_headers_raises_without_optional_header(self, clean_state):
        mock_pe = MagicMock()
        mock_pe.OPTIONAL_HEADER = None
        mock_pe.__data__ = b"\x00" * 100
        _make_pe_state(clean_state, pe_object=mock_pe)
        with pytest.raises(RuntimeError, match="requires a PE binary with valid headers"):
            _check_pe_object("test_tool", require_headers=True)

    def test_require_headers_passes_with_headers(self, clean_state):
        mock_pe = MagicMock()
        mock_pe.OPTIONAL_HEADER = MagicMock()
        mock_pe.__data__ = b"\x00" * 100
        _make_pe_state(clean_state, pe_object=mock_pe)
        # Should not raise
        _check_pe_object("test_tool", require_headers=True)

    def test_no_require_headers_passes_without_optional_header(self, clean_state):
        mock_pe = MagicMock()
        mock_pe.OPTIONAL_HEADER = None
        mock_pe.__data__ = b"\x00" * 100
        _make_pe_state(clean_state, pe_object=mock_pe)
        # Should not raise (require_headers=False)
        _check_pe_object("test_tool")


# ─── tools_pe_extended.py: pe_object None guard tests ────────────────

class TestPeExtendedNoneGuard:
    """Verify all pe_object-dependent tools raise RuntimeError when pe_object is None."""

    def test_get_section_permissions_no_pe_object(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_section_permissions
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(get_section_permissions(ctx))

    def test_get_pe_metadata_no_pe_object(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_pe_metadata
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(get_pe_metadata(ctx))

    def test_extract_resources_no_pe_object(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import extract_resources
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(extract_resources(ctx))

    def test_extract_manifest_no_pe_object(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import extract_manifest
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(extract_manifest(ctx))

    def test_get_load_config_details_no_pe_object(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_load_config_details
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(get_load_config_details(ctx))

    def test_extract_wide_strings_no_pe_object(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import extract_wide_strings
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(extract_wide_strings(ctx))

    def test_detect_format_strings_no_pe_object(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_format_strings
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(detect_format_strings(ctx))

    def test_detect_compression_headers_no_pe_object(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_compression_headers
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(detect_compression_headers(ctx))

    def test_detect_crypto_constants_no_pe_object(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_crypto_constants
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(detect_crypto_constants(ctx))

    def test_analyze_entropy_by_offset_no_pe_object(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import analyze_entropy_by_offset
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(analyze_entropy_by_offset(ctx))

    def test_scan_for_api_hashes_no_pe_object(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import scan_for_api_hashes
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(scan_for_api_hashes(ctx))

    def test_get_import_hash_analysis_no_pe_object(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_import_hash_analysis
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(get_import_hash_analysis(ctx))


# ─── tools_pe_structure.py: pe_object None guard tests ───────────────

class TestPeStructureNoneGuard:
    def test_analyze_relocations_no_pe_object(self, ctx, clean_state):
        from arkana.mcp.tools_pe_structure import analyze_relocations
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(analyze_relocations(ctx))

    def test_analyze_seh_handlers_no_pe_object(self, ctx, clean_state):
        from arkana.mcp.tools_pe_structure import analyze_seh_handlers
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(analyze_seh_handlers(ctx))

    def test_analyze_debug_directory_no_pe_object(self, ctx, clean_state):
        from arkana.mcp.tools_pe_structure import analyze_debug_directory
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(analyze_debug_directory(ctx))


# ─── tools_pe_forensic.py: pe_object None guard tests ────────────────

class TestPeForensicNoneGuard:
    def test_parse_authenticode_no_pe_object(self, ctx, clean_state):
        from arkana.mcp.tools_pe_forensic import parse_authenticode
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(parse_authenticode(ctx))

    def test_unify_artifact_timeline_no_pe_object(self, ctx, clean_state):
        from arkana.mcp.tools_pe_forensic import unify_artifact_timeline
        _make_pe_state(clean_state, pe_object=None)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(unify_artifact_timeline(ctx))


# ─── Bug #2: exports type safety ─────────────────────────────────────

class TestExportsTypeSafety:
    def test_get_analyzed_file_summary_exports_as_list(self, ctx, clean_state):
        """Bug #2: exports stored as list should not crash get_analyzed_file_summary."""
        from arkana.mcp.tools_pe import get_analyzed_file_summary
        clean_state.filepath = "/tmp/test.exe"
        clean_state.pe_data = {
            "file_hashes": {"md5": "aaa", "sha256": "bbb", "sha1": "ccc"},
            "pe_header": {"machine_type": "AMD64", "entry_point": "0x1000"},
            "sections": [],
            "imports": {},
            "exports": [],  # <-- list, not dict
            "strings": [],
            "peid": {},
            "yara_matches": [],
        }
        # Should not crash — previously threw AttributeError: 'list' has no 'get'
        r = _run(get_analyzed_file_summary(ctx))
        assert isinstance(r, dict)
        assert r.get("export_symbol_count", 0) == 0

    def test_get_analyzed_file_summary_exports_as_dict(self, ctx, clean_state):
        """Normal case: exports as dict with symbols list."""
        from arkana.mcp.tools_pe import get_analyzed_file_summary
        clean_state.filepath = "/tmp/test.exe"
        clean_state.pe_data = {
            "file_hashes": {"md5": "aaa", "sha256": "bbb", "sha1": "ccc"},
            "pe_header": {"machine_type": "AMD64", "entry_point": "0x1000"},
            "sections": [],
            "imports": {},
            "exports": {"symbols": [{"name": "DllMain", "ordinal": 1}]},
            "strings": [],
            "peid": {},
            "yara_matches": [],
        }
        r = _run(get_analyzed_file_summary(ctx))
        assert isinstance(r, dict)
        assert r.get("export_symbol_count") == 1

    def test_get_analyzed_file_summary_exports_none(self, ctx, clean_state):
        """Edge case: exports is None."""
        from arkana.mcp.tools_pe import get_analyzed_file_summary
        clean_state.filepath = "/tmp/test.exe"
        clean_state.pe_data = {
            "file_hashes": {"md5": "aaa", "sha256": "bbb", "sha1": "ccc"},
            "pe_header": {"machine_type": "AMD64", "entry_point": "0x1000"},
            "sections": [],
            "imports": {},
            "exports": None,
            "strings": [],
            "peid": {},
            "yara_matches": [],
        }
        r = _run(get_analyzed_file_summary(ctx))
        assert isinstance(r, dict)
        assert r.get("export_symbol_count", 0) == 0

    def test_get_analyzed_file_summary_exports_empty_dict(self, ctx, clean_state):
        """Edge case: exports is empty dict (no symbols key)."""
        from arkana.mcp.tools_pe import get_analyzed_file_summary
        clean_state.filepath = "/tmp/test.exe"
        clean_state.pe_data = {
            "file_hashes": {"md5": "aaa", "sha256": "bbb", "sha1": "ccc"},
            "pe_header": {"machine_type": "AMD64", "entry_point": "0x1000"},
            "sections": [],
            "imports": {},
            "exports": {},
            "strings": [],
            "peid": {},
            "yara_matches": [],
        }
        r = _run(get_analyzed_file_summary(ctx))
        assert isinstance(r, dict)
        assert r.get("export_symbol_count", 0) == 0
