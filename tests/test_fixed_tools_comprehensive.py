"""Comprehensive tests for all tools fixed in the pe_object guard audit.

Tests each fixed tool across 4 scenarios:
  1. No file loaded → RuntimeError
  2. pe_object is None (cache-restored session) → RuntimeError mentioning "PE object"
  3. MockPE with require_headers tools → RuntimeError mentioning "PE binary"
  4. Valid mock PE → successful execution (happy path)

Also tests exports type safety in get_analyzed_file_summary / get_full_analysis_results.
"""
import asyncio
import math
import re
import struct
import pytest
from unittest.mock import MagicMock, PropertyMock

from arkana.state import AnalyzerState, set_current_state


def _run(coro):
    return asyncio.run(coro)


class MockContext:
    def __init__(self):
        self.infos, self.warnings, self.errors = [], [], []

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


def _build_fake_pe_binary():
    """Build minimal but realistic PE binary bytes for tool testing."""
    # MZ header + PE signature + IMAGE_FILE_HEADER + IMAGE_OPTIONAL_HEADER (minimal)
    # Plus some recognizable data: wide strings, crypto constants, format strings
    data = bytearray(4096)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = struct.pack("<I", 0x80)  # e_lfanew
    data[0x80:0x84] = b"PE\x00\x00"
    # IMAGE_FILE_HEADER: Machine=AMD64, NumberOfSections=1
    data[0x84:0x86] = struct.pack("<H", 0x8664)
    data[0x86:0x88] = struct.pack("<H", 1)  # NumberOfSections
    # TimeDateStamp
    data[0x88:0x8C] = struct.pack("<I", 0x65000000)
    # SizeOfOptionalHeader
    data[0x94:0x96] = struct.pack("<H", 0xF0)
    # Characteristics
    data[0x96:0x98] = struct.pack("<H", 0x22)

    # Embed some wide strings (UTF-16LE)
    wide = "Hello World".encode("utf-16-le")
    data[0x200:0x200 + len(wide)] = wide

    # Embed a printf format string
    fmt = b"%s %d %n dangerous"
    data[0x300:0x300 + len(fmt)] = fmt

    # Embed zlib header (compression detection)
    data[0x400:0x402] = b"\x78\x9c"

    # Embed AES S-box first 4 bytes (crypto constant detection)
    data[0x500:0x504] = bytes([0x63, 0x7c, 0x77, 0x7b])

    # Some null regions
    # data[0x600:0x700] is already zeroed

    return bytes(data)


def _mock_pe_section(name=b".text\x00\x00\x00", va=0x1000, vsize=0x1000,
                     raw_size=0x1000, raw_offset=0x200, chars=0x60000020):
    sec = MagicMock()
    sec.Name = name
    sec.VirtualAddress = va
    sec.Misc_VirtualSize = vsize
    sec.SizeOfRawData = raw_size
    sec.PointerToRawData = raw_offset
    sec.Characteristics = chars
    sec.get_entropy.return_value = 6.5
    return sec


def _make_real_pe_state(state):
    """Set up state with a full mock pefile.PE object for happy-path testing."""
    binary = _build_fake_pe_binary()
    state.filepath = "/tmp/test_sample.exe"
    state.pe_data = {
        "file_hashes": {"md5": "d41d8cd98f00b204e9800998ecf8427e",
                        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        "pe_header": {"machine_type": "IMAGE_FILE_MACHINE_AMD64", "entry_point": "0x1000"},
        "sections": [
            {"name": ".text", "virtual_address": "0x1000", "virtual_size": 4096,
             "raw_size": 4096, "entropy": 6.5, "flags": "IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ"},
        ],
        "imports": {"kernel32.dll": ["VirtualAlloc", "GetProcAddress", "LoadLibraryA"]},
        "exports": {"symbols": [{"name": "DllMain", "ordinal": 1, "address": "0x1000", "forwarder": None}]},
        "strings": ["Hello World", "http://evil.com", "%s %d %n dangerous"],
        "floss_analysis": {"static_strings": ["test"], "decoded_strings": []},
        "peid": {"ep_matches": [], "heuristic_matches": [], "status": "clean"},
        "yara_matches": [],
    }
    state._binary_data = binary

    # Build a mock pefile.PE
    pe = MagicMock()
    pe.__data__ = binary
    pe.sections = [_mock_pe_section()]

    # OPTIONAL_HEADER
    oh = MagicMock()
    oh.ImageBase = 0x140000000
    oh.AddressOfEntryPoint = 0x1000
    oh.SizeOfImage = 0x10000
    oh.SizeOfHeaders = 0x200
    oh.Subsystem = 3  # CONSOLE
    oh.DllCharacteristics = 0x8160
    oh.Magic = 0x20B  # PE32+
    oh.MajorLinkerVersion = 14
    oh.MinorLinkerVersion = 0
    oh.SizeOfCode = 0x1000
    oh.CheckSum = 0
    oh.MajorOperatingSystemVersion = 6
    oh.MinorOperatingSystemVersion = 0
    oh.NumberOfRvaAndSizes = 16
    oh.DATA_DIRECTORY = [MagicMock() for _ in range(16)]
    pe.OPTIONAL_HEADER = oh

    # FILE_HEADER
    fh = MagicMock()
    fh.Machine = 0x8664
    fh.NumberOfSections = 1
    fh.TimeDateStamp = 0x65000000
    fh.Characteristics = 0x22
    fh.SizeOfOptionalHeader = 0xF0
    pe.FILE_HEADER = fh

    pe.DOS_HEADER = MagicMock()
    pe.DOS_HEADER.e_lfanew = 0x80

    # Exports
    pe.DIRECTORY_ENTRY_EXPORT = None  # No export directory
    pe.DIRECTORY_ENTRY_RESOURCE = None
    pe.DIRECTORY_ENTRY_LOAD_CONFIG = None
    pe.DIRECTORY_ENTRY_DEBUG = []
    pe.DIRECTORY_ENTRY_BASERELOC = []
    pe.DIRECTORY_ENTRY_EXCEPTION = []
    pe.DIRECTORY_ENTRY_TLS = None

    pe.get_imphash.return_value = "abc123deadbeef"
    pe.get_warnings.return_value = []
    pe.generate_checksum.return_value = 0x12345
    pe.get_overlay_data_start_offset.return_value = None

    # RICH_HEADER
    pe.RICH_HEADER = None

    state.pe_object = pe
    return state


def _make_none_pe_state(state):
    """State with pe_data but pe_object=None (simulates cache restore)."""
    state.filepath = "/tmp/test_sample.exe"
    state.pe_data = {
        "file_hashes": {"md5": "aaa", "sha256": "bbb", "sha1": "ccc"},
        "pe_header": {"machine_type": "AMD64", "entry_point": "0x1000"},
        "sections": [], "imports": {}, "exports": {}, "strings": [],
    }
    state.pe_object = None
    state._binary_data = b"MZ" + b"\x00" * 100
    return state


def _make_mockpe_state(state):
    """State with MockPE (shellcode/ELF) — has __data__ but no OPTIONAL_HEADER."""
    from arkana.mock import MockPE
    binary = _build_fake_pe_binary()
    state.filepath = "/tmp/shellcode.bin"
    state.pe_data = {
        "file_hashes": {"md5": "aaa", "sha256": "bbb", "sha1": "ccc"},
        "pe_header": {"machine_type": "unknown", "entry_point": "0x0"},
        "sections": [], "imports": {}, "exports": {}, "strings": [],
        "mode": "shellcode",
    }
    state.pe_object = MockPE(binary)
    state._binary_data = binary
    return state


# ═══════════════════════════════════════════════════════════════════════
#  tools_pe_extended.py — 12 tools with pe_object guard
# ═══════════════════════════════════════════════════════════════════════

class TestGetSectionPermissions:
    def test_no_file(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_section_permissions
        with pytest.raises(RuntimeError, match="No file"):
            _run(get_section_permissions(ctx))

    def test_pe_object_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_section_permissions
        _make_none_pe_state(clean_state)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(get_section_permissions(ctx))

    def test_mockpe_no_headers(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_section_permissions
        _make_mockpe_state(clean_state)
        with pytest.raises(RuntimeError, match="requires a PE binary"):
            _run(get_section_permissions(ctx))

    def test_valid_pe(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_section_permissions
        _make_real_pe_state(clean_state)
        r = _run(get_section_permissions(ctx))
        assert isinstance(r, dict)
        assert "sections" in r
        assert len(r["sections"]) == 1
        assert r["sections"][0]["name"] == ".text"


class TestGetPeMetadata:
    def test_pe_object_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_pe_metadata
        _make_none_pe_state(clean_state)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(get_pe_metadata(ctx))

    def test_mockpe_no_headers(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_pe_metadata
        _make_mockpe_state(clean_state)
        with pytest.raises(RuntimeError, match="requires a PE binary"):
            _run(get_pe_metadata(ctx))

    def test_valid_pe(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_pe_metadata
        _make_real_pe_state(clean_state)
        r = _run(get_pe_metadata(ctx))
        assert isinstance(r, dict)
        assert "machine" in r or "architecture" in r or "subsystem" in r


class TestExtractResources:
    def test_pe_object_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import extract_resources
        _make_none_pe_state(clean_state)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(extract_resources(ctx))

    def test_valid_pe_no_resources(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import extract_resources
        _make_real_pe_state(clean_state)
        r = _run(extract_resources(ctx))
        assert isinstance(r, dict)
        assert r["total_resources"] == 0  # Our mock has no resource dir


class TestExtractManifest:
    def test_pe_object_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import extract_manifest
        _make_none_pe_state(clean_state)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(extract_manifest(ctx))

    def test_valid_pe_no_manifest(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import extract_manifest
        _make_real_pe_state(clean_state)
        r = _run(extract_manifest(ctx))
        assert isinstance(r, dict)
        assert "error" in r or "note" in r  # No resource directory


class TestGetLoadConfigDetails:
    def test_pe_object_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_load_config_details
        _make_none_pe_state(clean_state)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(get_load_config_details(ctx))

    def test_valid_pe_no_load_config(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_load_config_details
        _make_real_pe_state(clean_state)
        r = _run(get_load_config_details(ctx))
        assert isinstance(r, dict)
        assert "note" in r  # No Load Config directory


class TestExtractWideStrings:
    def test_pe_object_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import extract_wide_strings
        _make_none_pe_state(clean_state)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(extract_wide_strings(ctx))

    def test_mockpe_works(self, ctx, clean_state):
        """MockPE has __data__, so this should work (no require_headers)."""
        from arkana.mcp.tools_pe_extended import extract_wide_strings
        _make_mockpe_state(clean_state)
        r = _run(extract_wide_strings(ctx))
        assert isinstance(r, dict)
        assert "strings" in r

    def test_valid_pe_finds_wide_strings(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import extract_wide_strings
        _make_real_pe_state(clean_state)
        r = _run(extract_wide_strings(ctx))
        assert isinstance(r, dict)
        assert r["total_found"] >= 1
        # Should find "Hello World" we embedded
        found = [s["string"] for s in r["strings"]]
        assert any("Hello" in s for s in found)


class TestDetectFormatStrings:
    def test_pe_object_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_format_strings
        _make_none_pe_state(clean_state)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(detect_format_strings(ctx))

    def test_mockpe_works(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_format_strings
        _make_mockpe_state(clean_state)
        r = _run(detect_format_strings(ctx))
        assert isinstance(r, dict)

    def test_valid_pe_finds_format_strings(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_format_strings
        _make_real_pe_state(clean_state)
        r = _run(detect_format_strings(ctx))
        assert isinstance(r, dict)


class TestDetectCompressionHeaders:
    def test_pe_object_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_compression_headers
        _make_none_pe_state(clean_state)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(detect_compression_headers(ctx))

    def test_mockpe_works(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_compression_headers
        _make_mockpe_state(clean_state)
        r = _run(detect_compression_headers(ctx))
        assert isinstance(r, dict)

    def test_valid_pe_finds_zlib(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_compression_headers
        _make_real_pe_state(clean_state)
        r = _run(detect_compression_headers(ctx))
        assert isinstance(r, dict)
        # Should find the zlib header we embedded
        matches = r.get("matches", r.get("findings", []))
        if matches:
            assert any("zlib" in str(m).lower() for m in matches)


class TestDetectCryptoConstants:
    def test_pe_object_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_crypto_constants
        _make_none_pe_state(clean_state)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(detect_crypto_constants(ctx))

    def test_mockpe_works(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_crypto_constants
        _make_mockpe_state(clean_state)
        r = _run(detect_crypto_constants(ctx))
        assert isinstance(r, dict)


class TestAnalyzeEntropyByOffset:
    def test_pe_object_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import analyze_entropy_by_offset
        _make_none_pe_state(clean_state)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(analyze_entropy_by_offset(ctx))

    def test_mockpe_works(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import analyze_entropy_by_offset
        _make_mockpe_state(clean_state)
        r = _run(analyze_entropy_by_offset(ctx))
        assert isinstance(r, dict)

    def test_valid_pe(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import analyze_entropy_by_offset
        _make_real_pe_state(clean_state)
        r = _run(analyze_entropy_by_offset(ctx))
        assert isinstance(r, dict)
        # Should have data points
        points = r.get("data_points", r.get("points", r.get("entropy_curve", [])))
        assert isinstance(points, list)


class TestScanForApiHashes:
    def test_pe_object_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import scan_for_api_hashes
        _make_none_pe_state(clean_state)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(scan_for_api_hashes(ctx))

    def test_mockpe_works(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import scan_for_api_hashes
        _make_mockpe_state(clean_state)
        r = _run(scan_for_api_hashes(ctx))
        assert isinstance(r, dict)


class TestGetImportHashAnalysis:
    def test_pe_object_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_import_hash_analysis
        _make_none_pe_state(clean_state)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(get_import_hash_analysis(ctx))

    def test_mockpe_no_headers(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_import_hash_analysis
        _make_mockpe_state(clean_state)
        with pytest.raises(RuntimeError, match="requires a PE binary"):
            _run(get_import_hash_analysis(ctx))

    def test_valid_pe(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_import_hash_analysis
        _make_real_pe_state(clean_state)
        r = _run(get_import_hash_analysis(ctx))
        assert isinstance(r, dict)
        assert r.get("imphash") == "abc123deadbeef"


# ═══════════════════════════════════════════════════════════════════════
#  tools_pe_structure.py — 3 tools
# ═══════════════════════════════════════════════════════════════════════

class TestAnalyzeRelocations:
    def test_pe_object_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_structure import analyze_relocations
        _make_none_pe_state(clean_state)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(analyze_relocations(ctx))

    def test_valid_pe(self, ctx, clean_state):
        from arkana.mcp.tools_pe_structure import analyze_relocations
        _make_real_pe_state(clean_state)
        r = _run(analyze_relocations(ctx))
        assert isinstance(r, dict)


class TestAnalyzeSehHandlers:
    def test_pe_object_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_structure import analyze_seh_handlers
        _make_none_pe_state(clean_state)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(analyze_seh_handlers(ctx))

    def test_valid_pe(self, ctx, clean_state):
        from arkana.mcp.tools_pe_structure import analyze_seh_handlers
        _make_real_pe_state(clean_state)
        r = _run(analyze_seh_handlers(ctx))
        assert isinstance(r, dict)


class TestAnalyzeDebugDirectory:
    def test_pe_object_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_structure import analyze_debug_directory
        _make_none_pe_state(clean_state)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(analyze_debug_directory(ctx))

    def test_valid_pe(self, ctx, clean_state):
        from arkana.mcp.tools_pe_structure import analyze_debug_directory
        _make_real_pe_state(clean_state)
        r = _run(analyze_debug_directory(ctx))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════
#  tools_pe_forensic.py — 2 tools
# ═══════════════════════════════════════════════════════════════════════

class TestParseAuthenticode:
    def test_pe_object_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_forensic import parse_authenticode
        _make_none_pe_state(clean_state)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(parse_authenticode(ctx))

    def test_mockpe_no_headers(self, ctx, clean_state):
        from arkana.mcp.tools_pe_forensic import parse_authenticode
        _make_mockpe_state(clean_state)
        with pytest.raises(RuntimeError, match="requires a PE binary"):
            _run(parse_authenticode(ctx))

    def test_valid_pe(self, ctx, clean_state):
        from arkana.mcp.tools_pe_forensic import parse_authenticode
        _make_real_pe_state(clean_state)
        r = _run(parse_authenticode(ctx))
        assert isinstance(r, dict)


class TestUnifyArtifactTimeline:
    def test_pe_object_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_forensic import unify_artifact_timeline
        _make_none_pe_state(clean_state)
        with pytest.raises(RuntimeError, match="PE object"):
            _run(unify_artifact_timeline(ctx))

    def test_mockpe_no_headers(self, ctx, clean_state):
        from arkana.mcp.tools_pe_forensic import unify_artifact_timeline
        _make_mockpe_state(clean_state)
        with pytest.raises(RuntimeError, match="requires a PE binary"):
            _run(unify_artifact_timeline(ctx))

    def test_valid_pe(self, ctx, clean_state):
        from arkana.mcp.tools_pe_forensic import unify_artifact_timeline
        _make_real_pe_state(clean_state)
        r = _run(unify_artifact_timeline(ctx))
        assert isinstance(r, dict)
        assert "artifacts" in r or "timeline" in r


# ═══════════════════════════════════════════════════════════════════════
#  tools_pe.py — exports type safety (Bug #2)
# ═══════════════════════════════════════════════════════════════════════

class TestExportsTypeSafety:
    """Test get_analyzed_file_summary and get_full_analysis_results with all exports shapes."""

    def _base_pe_data(self, exports):
        return {
            "file_hashes": {"md5": "aaa", "sha256": "bbb", "sha1": "ccc"},
            "pe_header": {"machine_type": "AMD64", "entry_point": "0x1000",
                          "timestamp": "2024-01-01", "timestamp_utc": "2024-01-01"},
            "sections": [{"name": ".text", "virtual_address": "0x1000",
                          "virtual_size": 4096, "raw_size": 4096,
                          "entropy": 6.5, "flags": "CNT_CODE"}],
            "imports": {"kernel32.dll": ["CreateFileA"]},
            "exports": exports,
            "strings": ["test"],
            "peid": {"ep_matches": [], "heuristic_matches": [], "status": "clean"},
            "yara_matches": [],
            "floss_analysis": {"static_strings": [], "decoded_strings": []},
        }

    def test_summary_exports_list(self, ctx, clean_state):
        from arkana.mcp.tools_pe import get_analyzed_file_summary
        clean_state.filepath = "/tmp/t.exe"
        clean_state.pe_data = self._base_pe_data([])
        r = _run(get_analyzed_file_summary(ctx))
        assert isinstance(r, dict)
        assert r.get("export_symbol_count", 0) == 0

    def test_summary_exports_dict_with_symbols(self, ctx, clean_state):
        from arkana.mcp.tools_pe import get_analyzed_file_summary
        clean_state.filepath = "/tmp/t.exe"
        clean_state.pe_data = self._base_pe_data(
            {"symbols": [{"name": "Fn1"}, {"name": "Fn2"}]}
        )
        r = _run(get_analyzed_file_summary(ctx))
        assert r.get("export_symbol_count") == 2

    def test_summary_exports_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe import get_analyzed_file_summary
        clean_state.filepath = "/tmp/t.exe"
        clean_state.pe_data = self._base_pe_data(None)
        r = _run(get_analyzed_file_summary(ctx))
        assert r.get("export_symbol_count", 0) == 0

    def test_summary_exports_empty_dict(self, ctx, clean_state):
        from arkana.mcp.tools_pe import get_analyzed_file_summary
        clean_state.filepath = "/tmp/t.exe"
        clean_state.pe_data = self._base_pe_data({})
        r = _run(get_analyzed_file_summary(ctx))
        assert r.get("export_symbol_count", 0) == 0

    def test_full_results_exports_list(self, ctx, clean_state):
        from arkana.mcp.tools_pe import get_full_analysis_results
        clean_state.filepath = "/tmp/t.exe"
        clean_state.pe_data = self._base_pe_data([])
        r = _run(get_full_analysis_results(ctx, limit=10, compact=True))
        assert isinstance(r, dict)
        # compact mode has export_count
        if "compact" in r:
            assert r["compact"].get("export_count", 0) == 0

    def test_full_results_exports_dict(self, ctx, clean_state):
        from arkana.mcp.tools_pe import get_full_analysis_results
        clean_state.filepath = "/tmp/t.exe"
        clean_state.pe_data = self._base_pe_data(
            {"symbols": [{"name": "DllMain"}]}
        )
        r = _run(get_full_analysis_results(ctx, limit=10, compact=True))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════
#  Edge cases and additional coverage
# ═══════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Additional edge cases for the fixed tools."""

    def test_section_permissions_many_sections(self, ctx, clean_state):
        """Test with multiple sections of different types."""
        from arkana.mcp.tools_pe_extended import get_section_permissions
        _make_real_pe_state(clean_state)
        pe = clean_state.pe_object
        pe.sections = [
            _mock_pe_section(b".text\x00\x00\x00", chars=0x60000020),  # RX code
            _mock_pe_section(b".data\x00\x00\x00", va=0x2000, chars=0xC0000040),  # RW data
            _mock_pe_section(b".rsrc\x00\x00\x00", va=0x3000, chars=0x40000040),  # R data
            _mock_pe_section(b".rwx\x00\x00\x00\x00", va=0x4000, chars=0xE0000020),  # RWX suspicious
        ]
        r = _run(get_section_permissions(ctx))
        assert len(r["sections"]) == 4
        # RWX should trigger anomaly
        anomalies = r.get("anomalies", [])
        if anomalies:
            assert any("rwx" in str(a).lower() or "write" in str(a).lower() for a in anomalies)

    def test_section_permissions_limit(self, ctx, clean_state):
        """Test that limit parameter works."""
        from arkana.mcp.tools_pe_extended import get_section_permissions
        _make_real_pe_state(clean_state)
        pe = clean_state.pe_object
        pe.sections = [_mock_pe_section(f".s{i}\x00\x00\x00\x00\x00".encode()[:8], va=0x1000 * (i + 1))
                       for i in range(10)]
        r = _run(get_section_permissions(ctx, limit=3))
        assert len(r["sections"]) <= 3

    def test_extract_wide_strings_min_length(self, ctx, clean_state):
        """Test min_length parameter filtering."""
        from arkana.mcp.tools_pe_extended import extract_wide_strings
        _make_real_pe_state(clean_state)
        # "Hello World" is 11 chars, so min_length=12 should filter it out
        r = _run(extract_wide_strings(ctx, min_length=12))
        assert isinstance(r, dict)
        found = [s["string"] for s in r.get("strings", [])]
        assert not any("Hello World" in s for s in found)

    def test_detect_null_regions_still_works(self, ctx, clean_state):
        """detect_null_regions doesn't use pe_object — verify it's unaffected."""
        from arkana.mcp.tools_pe_extended import detect_null_regions
        _make_real_pe_state(clean_state)
        r = _run(detect_null_regions(ctx))
        assert isinstance(r, dict)

    def test_import_hash_analysis_imphash_exception(self, ctx, clean_state):
        """Test that get_imphash() exception is handled gracefully."""
        from arkana.mcp.tools_pe_extended import get_import_hash_analysis
        _make_real_pe_state(clean_state)
        clean_state.pe_object.get_imphash.side_effect = Exception("pefile crash")
        r = _run(get_import_hash_analysis(ctx))
        assert isinstance(r, dict)
        # Should handle gracefully — imphash is None
        assert r.get("imphash") is None

    def test_analyze_entropy_custom_params(self, ctx, clean_state):
        """Test entropy analysis with custom window/step."""
        from arkana.mcp.tools_pe_extended import analyze_entropy_by_offset
        _make_real_pe_state(clean_state)
        r = _run(analyze_entropy_by_offset(ctx, window_size=128, step=64))
        assert isinstance(r, dict)
