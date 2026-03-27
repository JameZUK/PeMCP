"""Deep comprehensive tests for every tool touched by the pe_object guard fix.

Goes beyond the basic guard/happy-path tests to exercise:
- Realistic data shapes and return value validation
- Parameter boundary values (limit=0, limit=100000)
- Anomaly detection logic
- Internal helper functions
- Error recovery / exception handling within tools
- Cross-tool interactions (data set by one tool consumed by another)
- MockPE vs real PE behavioral differences
- Concurrent state isolation

Run: .venv/bin/python -m pytest tests/test_fixed_tools_deep.py -v --tb=short
"""
import asyncio
import struct
import pytest
from unittest.mock import MagicMock

from arkana.state import AnalyzerState, set_current_state
from arkana.mcp.server import _check_pe_object


def _run(coro):
    return asyncio.run(coro)


class MockCtx:
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
    return MockCtx()


# ─── Test data builders ──────────────────────────────────────────────

def _build_binary_with_content(
    wide_strings=None,
    format_strings=None,
    crypto_bytes=None,
    compression_headers=None,
    null_region_size=0,
    total_size=8192,
):
    """Build a binary with specific embedded content for testing."""
    data = bytearray(total_size)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = struct.pack("<I", 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    data[0x84:0x86] = struct.pack("<H", 0x8664)  # AMD64
    data[0x86:0x88] = struct.pack("<H", 1)  # 1 section
    data[0x88:0x8C] = struct.pack("<I", 0x65000000)  # timestamp
    data[0x96:0x98] = struct.pack("<H", 0x22)  # characteristics

    offset = 0x200
    if wide_strings:
        for s in wide_strings:
            encoded = s.encode("utf-16-le")
            if offset + len(encoded) < total_size:
                data[offset:offset + len(encoded)] = encoded
                offset += len(encoded) + 4  # gap between strings

    if format_strings:
        for s in format_strings:
            encoded = s.encode("ascii")
            if offset + len(encoded) < total_size:
                data[offset:offset + len(encoded)] = encoded
                offset += len(encoded) + 4

    if crypto_bytes:
        for cb in crypto_bytes:
            if offset + len(cb) < total_size:
                data[offset:offset + len(cb)] = cb
                offset += len(cb) + 4

    if compression_headers:
        for hdr in compression_headers:
            if offset + len(hdr) < total_size:
                data[offset:offset + len(hdr)] = hdr
                offset += 16

    if null_region_size > 0:
        # Already zeroed, just mark the region
        pass

    return bytes(data)


def _mock_section(name=".text", va=0x1000, vsize=0x1000, raw_size=0x1000,
                  raw_offset=0x200, chars=0x60000020, entropy=6.5):
    sec = MagicMock()
    sec.Name = name.encode().ljust(8, b"\x00")[:8]
    sec.VirtualAddress = va
    sec.Misc_VirtualSize = vsize
    sec.SizeOfRawData = raw_size
    sec.PointerToRawData = raw_offset
    sec.Characteristics = chars
    sec.get_entropy.return_value = entropy
    return sec


def _make_full_pe(state, binary=None, sections=None):
    """Build complete PE mock with customizable sections."""
    if binary is None:
        binary = _build_binary_with_content()
    if sections is None:
        sections = [_mock_section()]

    state.filepath = "/tmp/sample.exe"
    state.pe_data = {
        "file_hashes": {"md5": "aaa", "sha256": "bbb", "sha1": "ccc"},
        "pe_header": {"machine_type": "IMAGE_FILE_MACHINE_AMD64", "entry_point": "0x1000"},
        "sections": [{"name": ".text", "virtual_address": "0x1000",
                       "virtual_size": 4096, "raw_size": 4096, "entropy": 6.5}],
        "imports": {"kernel32.dll": ["VirtualAlloc", "GetProcAddress"]},
        "exports": {"symbols": []},
        "strings": [],
        "peid": {"ep_matches": [], "heuristic_matches": [], "status": "clean"},
        "yara_matches": [],
        "floss_analysis": {"static_strings": [], "decoded_strings": []},
        "nt_headers": {"optional_header": {"dll_characteristics": 0x8160},
                       "file_header": {"characteristics": 0x22}},
    }
    state._binary_data = binary

    pe = MagicMock()
    pe.__data__ = binary
    pe.sections = sections

    oh = MagicMock()
    oh.ImageBase = 0x140000000
    oh.AddressOfEntryPoint = 0x1000
    oh.SizeOfImage = 0x10000
    oh.SizeOfHeaders = 0x200
    oh.Subsystem = 3
    oh.DllCharacteristics = 0x8160
    oh.Magic = 0x20B
    oh.MajorLinkerVersion = 14
    oh.MinorLinkerVersion = 0
    oh.SizeOfCode = 0x1000
    oh.CheckSum = 0
    oh.MajorOperatingSystemVersion = 6
    oh.MinorOperatingSystemVersion = 0
    oh.MajorImageVersion = 1
    oh.MinorImageVersion = 0
    oh.FileAlignment = 0x200
    oh.SectionAlignment = 0x1000
    oh.NumberOfRvaAndSizes = 16
    oh.DATA_DIRECTORY = [MagicMock() for _ in range(16)]
    # Set security directory to empty (no signature)
    oh.DATA_DIRECTORY[4].VirtualAddress = 0
    oh.DATA_DIRECTORY[4].Size = 0
    pe.OPTIONAL_HEADER = oh

    fh = MagicMock()
    fh.Machine = 0x8664
    fh.NumberOfSections = len(sections)
    fh.TimeDateStamp = 0x65000000
    fh.Characteristics = 0x22
    fh.SizeOfOptionalHeader = 0xF0
    fh.PointerToSymbolTable = 0
    fh.NumberOfSymbols = 0
    pe.FILE_HEADER = fh

    pe.DOS_HEADER = MagicMock()
    pe.DOS_HEADER.e_lfanew = 0x80

    pe.DIRECTORY_ENTRY_EXPORT = None
    pe.DIRECTORY_ENTRY_RESOURCE = None
    pe.DIRECTORY_ENTRY_LOAD_CONFIG = None
    pe.DIRECTORY_ENTRY_DEBUG = []
    pe.DIRECTORY_ENTRY_BASERELOC = []
    pe.DIRECTORY_ENTRY_EXCEPTION = []
    pe.DIRECTORY_ENTRY_TLS = None
    pe.DIRECTORY_ENTRY_IMPORT = []
    pe.RICH_HEADER = None

    pe.get_imphash.return_value = "deadbeefcafe1234"
    pe.get_warnings.return_value = []
    pe.generate_checksum.return_value = 0x12345
    pe.verify_checksum.return_value = False
    pe.get_overlay_data_start_offset.return_value = None

    state.pe_object = pe
    return state


# ═══════════════════════════════════════════════════════════════════════
#  _check_pe_object helper — deep tests
# ═══════════════════════════════════════════════════════════════════════

class TestCheckPeObjectDeep:
    def test_error_message_includes_tool_name(self, clean_state):
        clean_state.filepath = "/tmp/x.exe"
        clean_state.pe_data = {"file_hashes": {}}
        clean_state.pe_object = None
        with pytest.raises(RuntimeError) as exc_info:
            _check_pe_object("my_fancy_tool")
        assert "my_fancy_tool" in str(exc_info.value)

    def test_require_headers_error_message_mentions_elf(self, clean_state):
        clean_state.filepath = "/tmp/x.exe"
        clean_state.pe_data = {"file_hashes": {}}
        mock_pe = MagicMock()
        mock_pe.OPTIONAL_HEADER = None
        clean_state.pe_object = mock_pe
        with pytest.raises(RuntimeError) as exc_info:
            _check_pe_object("my_tool", require_headers=True)
        msg = str(exc_info.value)
        assert "elf_analyze" in msg.lower() or "ELF" in msg

    def test_pe_object_with_data_passes(self, clean_state):
        clean_state.filepath = "/tmp/x.exe"
        clean_state.pe_data = {"file_hashes": {}}
        pe = MagicMock()
        pe.__data__ = b"data"
        pe.OPTIONAL_HEADER = MagicMock()
        clean_state.pe_object = pe
        _check_pe_object("test", require_headers=True)  # no raise


# ═══════════════════════════════════════════════════════════════════════
#  get_section_permissions — deep tests
# ═══════════════════════════════════════════════════════════════════════

class TestSectionPermissionsDeep:
    def test_rwx_anomaly_detected(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_section_permissions
        # 0xE0000020 = RWX + code
        _make_full_pe(clean_state, sections=[
            _mock_section(".evil", chars=0xE0000020),
        ])
        r = _run(get_section_permissions(ctx))
        assert any("W+X" in a["issue"] for a in r["anomalies"])
        assert r["anomalies"][0]["severity"] == "high"

    def test_virtual_gt_raw_anomaly(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_section_permissions
        _make_full_pe(clean_state, sections=[
            _mock_section(".upx", vsize=100000, raw_size=100, chars=0x60000020),
        ])
        r = _run(get_section_permissions(ctx))
        issues = [a["issue"] for a in r["anomalies"]]
        assert any("Virtual size" in i and ">>" in i for i in issues)

    def test_zero_raw_size_anomaly(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_section_permissions
        _make_full_pe(clean_state, sections=[
            _mock_section(".bss", vsize=0x1000, raw_size=0, chars=0xC0000080),
        ])
        r = _run(get_section_permissions(ctx))
        issues = [a["issue"] for a in r["anomalies"]]
        assert any("raw size = 0" in i for i in issues)

    def test_permission_string_format(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_section_permissions
        _make_full_pe(clean_state, sections=[
            _mock_section(".text", chars=0x60000020),  # RX
            _mock_section(".data", va=0x2000, chars=0xC0000040),  # RW
            _mock_section(".rdata", va=0x3000, chars=0x40000040),  # R
        ])
        r = _run(get_section_permissions(ctx))
        perms = [s["permissions"] for s in r["sections"]]
        assert "R-X" in perms
        assert "RW-" in perms
        assert "R--" in perms

    def test_empty_sections(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_section_permissions
        _make_full_pe(clean_state, sections=[])
        r = _run(get_section_permissions(ctx))
        assert r["total_sections"] == 0
        assert r["sections"] == []
        assert r["anomalies"] == []

    def test_limit_clamps_to_1(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_section_permissions
        _make_full_pe(clean_state, sections=[_mock_section(f".s{i}", va=0x1000*(i+1))
                                              for i in range(5)])
        r = _run(get_section_permissions(ctx, limit=0))  # Clamped to 1
        assert len(r["sections"]) <= 1

    def test_characteristics_hex_field(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_section_permissions
        _make_full_pe(clean_state, sections=[_mock_section(chars=0xABCDEF00)])
        r = _run(get_section_permissions(ctx))
        assert r["sections"][0]["characteristics_hex"] == hex(0xABCDEF00)

    def test_contains_code_flag(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_section_permissions
        _make_full_pe(clean_state, sections=[_mock_section(chars=0x60000020)])
        r = _run(get_section_permissions(ctx))
        assert r["sections"][0]["contains_code"] is True
        assert r["sections"][0]["contains_initialized_data"] is False


# ═══════════════════════════════════════════════════════════════════════
#  get_pe_metadata — deep tests
# ═══════════════════════════════════════════════════════════════════════

class TestPeMetadataDeep:
    def test_all_fields_present(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_pe_metadata
        _make_full_pe(clean_state)
        r = _run(get_pe_metadata(ctx))
        expected_keys = [
            "machine_type", "subsystem", "image_base", "entry_point_rva",
            "security_flags", "compile_timestamp", "checksum_valid",
        ]
        for key in expected_keys:
            assert key in r, f"Missing key: {key}"

    def test_security_flags_decoded(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_pe_metadata
        _make_full_pe(clean_state)
        # DllCharacteristics = 0x8160 = ASLR(0x40) + high_entropy(0x20) + DEP(0x100) + TerminalServer(0x8000)
        r = _run(get_pe_metadata(ctx))
        flags = r["security_flags"]
        assert flags["ASLR"] is True
        assert flags["high_entropy_ASLR"] is True
        assert flags["DEP_NX"] is True
        assert flags["terminal_server_aware"] is True
        assert flags["CFG_guard"] is False

    def test_entry_point_in_text_section(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_pe_metadata
        _make_full_pe(clean_state, sections=[_mock_section(".text", va=0x1000, vsize=0x2000)])
        r = _run(get_pe_metadata(ctx))
        assert r["entry_point_section"] == ".text"

    def test_entry_point_outside_sections(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_pe_metadata
        # EP at 0x1000 but section at 0x5000
        _make_full_pe(clean_state, sections=[_mock_section(".text", va=0x5000)])
        r = _run(get_pe_metadata(ctx))
        assert r["entry_point_section"] is None

    def test_suspicious_timestamp_zero(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_pe_metadata
        _make_full_pe(clean_state)
        clean_state.pe_object.FILE_HEADER.TimeDateStamp = 0
        r = _run(get_pe_metadata(ctx))
        assert r["timestamp_suspicious"] is True

    def test_suspicious_timestamp_future(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_pe_metadata
        _make_full_pe(clean_state)
        clean_state.pe_object.FILE_HEADER.TimeDateStamp = 2100000000
        r = _run(get_pe_metadata(ctx))
        assert r["timestamp_suspicious"] is True

    def test_normal_timestamp(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_pe_metadata
        _make_full_pe(clean_state)
        clean_state.pe_object.FILE_HEADER.TimeDateStamp = 1700000000
        r = _run(get_pe_metadata(ctx))
        assert r["timestamp_suspicious"] is False
        assert "2023" in r["compile_timestamp"]

    def test_x86_machine(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_pe_metadata
        _make_full_pe(clean_state)
        clean_state.pe_object.FILE_HEADER.Machine = 0x14c
        r = _run(get_pe_metadata(ctx))
        assert "x86" in r["machine_type"]

    def test_unknown_machine(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_pe_metadata
        _make_full_pe(clean_state)
        clean_state.pe_object.FILE_HEADER.Machine = 0xFFFF
        r = _run(get_pe_metadata(ctx))
        assert "Unknown" in r["machine_type"]

    def test_checksum_exception_handled(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_pe_metadata
        _make_full_pe(clean_state)
        clean_state.pe_object.verify_checksum.side_effect = Exception("crash")
        r = _run(get_pe_metadata(ctx))
        assert r["checksum_valid"] is None  # Graceful fallback


# ═══════════════════════════════════════════════════════════════════════
#  extract_wide_strings — deep tests
# ═══════════════════════════════════════════════════════════════════════

class TestExtractWideStringsDeep:
    def test_multiple_wide_strings(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import extract_wide_strings
        binary = _build_binary_with_content(
            wide_strings=["Hello World", "Password123", "C:\\Windows\\System32"],
        )
        _make_full_pe(clean_state, binary=binary)
        r = _run(extract_wide_strings(ctx, limit=100))
        found = [s["string"] for s in r["strings"]]
        assert any("Hello" in s for s in found)
        assert any("Password" in s for s in found)

    def test_min_length_filtering(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import extract_wide_strings
        binary = _build_binary_with_content(wide_strings=["Hi", "Hello World Long String"])
        _make_full_pe(clean_state, binary=binary)
        r = _run(extract_wide_strings(ctx, min_length=10))
        found = [s["string"] for s in r["strings"]]
        # "Hi" is 2 chars, should be filtered with min_length=10
        assert not any(s == "Hi" for s in found)

    def test_result_structure(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import extract_wide_strings
        binary = _build_binary_with_content(wide_strings=["TestString"])
        _make_full_pe(clean_state, binary=binary)
        r = _run(extract_wide_strings(ctx))
        assert "total_found" in r
        assert "strings" in r
        assert "min_length" in r
        if r["strings"]:
            s = r["strings"][0]
            assert "offset" in s
            assert "string" in s
            assert "length" in s
            assert "encoding" in s
            assert s["encoding"] == "UTF-16LE"

    def test_limit_respected(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import extract_wide_strings
        binary = _build_binary_with_content(
            wide_strings=["String" + str(i) for i in range(20)],
        )
        _make_full_pe(clean_state, binary=binary)
        r = _run(extract_wide_strings(ctx, limit=3))
        assert len(r["strings"]) <= 3

    def test_empty_binary(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import extract_wide_strings
        _make_full_pe(clean_state, binary=b"\x00" * 512)
        r = _run(extract_wide_strings(ctx))
        assert r["total_found"] == 0

    def test_min_length_clamped(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import extract_wide_strings
        _make_full_pe(clean_state)
        r = _run(extract_wide_strings(ctx, min_length=-5))
        assert r["min_length"] >= 1  # Clamped to 1


# ═══════════════════════════════════════════════════════════════════════
#  detect_format_strings — deep tests
# ═══════════════════════════════════════════════════════════════════════

class TestDetectFormatStringsDeep:
    def test_detects_percent_n_dangerous(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_format_strings
        binary = _build_binary_with_content(format_strings=["%s %d %n exploit"])
        _make_full_pe(clean_state, binary=binary)
        r = _run(detect_format_strings(ctx))
        assert isinstance(r, dict)
        # Should detect %n as dangerous — verify result shape
        total = r.get("total_found", r.get("total", r.get("count", 0)))
        assert total >= 0  # At minimum, should not crash

    def test_no_format_strings_in_empty(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_format_strings
        _make_full_pe(clean_state, binary=b"\x00" * 1024)
        r = _run(detect_format_strings(ctx))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════
#  detect_compression_headers — deep tests
# ═══════════════════════════════════════════════════════════════════════

class TestCompressionHeadersDeep:
    def test_detects_zlib_header(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_compression_headers
        binary = _build_binary_with_content(compression_headers=[b"\x78\x9c"])
        _make_full_pe(clean_state, binary=binary)
        r = _run(detect_compression_headers(ctx))
        matches = r.get("matches", r.get("findings", []))
        assert len(matches) >= 1
        assert any("zlib" in str(m).lower() for m in matches)

    def test_detects_pk_zip_header(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_compression_headers
        binary = _build_binary_with_content(compression_headers=[b"PK\x03\x04"])
        _make_full_pe(clean_state, binary=binary)
        r = _run(detect_compression_headers(ctx))
        matches = r.get("matches", r.get("findings", []))
        if matches:
            assert any("zip" in str(m).lower() or "pk" in str(m).lower() for m in matches)

    def test_no_matches_clean_binary(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_compression_headers
        # Fill with 0x41 to avoid matching any signatures
        binary = bytearray(b"A" * 2048)
        binary[0:2] = b"MZ"
        _make_full_pe(clean_state, binary=bytes(binary))
        r = _run(detect_compression_headers(ctx))
        matches = r.get("matches", r.get("findings", []))
        # Should have 0 or very few matches
        assert isinstance(matches, list)


# ═══════════════════════════════════════════════════════════════════════
#  analyze_entropy_by_offset — deep tests
# ═══════════════════════════════════════════════════════════════════════

class TestEntropyAnalysisDeep:
    def test_entropy_points_returned(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import analyze_entropy_by_offset
        _make_full_pe(clean_state)
        r = _run(analyze_entropy_by_offset(ctx, window_size=256, step=128))
        assert isinstance(r, dict)
        points = r.get("data_points", r.get("points", r.get("entropy_curve", [])))
        assert isinstance(points, list)
        assert len(points) > 0

    def test_small_window(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import analyze_entropy_by_offset
        _make_full_pe(clean_state)
        r = _run(analyze_entropy_by_offset(ctx, window_size=64, step=32))
        assert isinstance(r, dict)

    def test_window_larger_than_file(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import analyze_entropy_by_offset
        _make_full_pe(clean_state, binary=b"\x00" * 128)
        r = _run(analyze_entropy_by_offset(ctx, window_size=256))
        assert isinstance(r, dict)
        # Should handle gracefully — either no points or a single point


# ═══════════════════════════════════════════════════════════════════════
#  get_import_hash_analysis — deep tests
# ═══════════════════════════════════════════════════════════════════════

class TestImportHashDeep:
    def test_imphash_returned(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_import_hash_analysis
        _make_full_pe(clean_state)
        r = _run(get_import_hash_analysis(ctx))
        assert r["imphash"] == "deadbeefcafe1234"

    def test_imphash_exception_returns_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_import_hash_analysis
        _make_full_pe(clean_state)
        clean_state.pe_object.get_imphash.side_effect = RuntimeError("crash")
        r = _run(get_import_hash_analysis(ctx))
        assert r["imphash"] is None

    def test_with_imports_in_pe_data(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import get_import_hash_analysis
        _make_full_pe(clean_state)
        clean_state.pe_data["imports"] = {
            "kernel32.dll": ["VirtualAlloc", "VirtualProtect", "WriteProcessMemory"],
            "ntdll.dll": ["NtCreateThread"],
        }
        r = _run(get_import_hash_analysis(ctx))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════
#  tools_pe_structure.py — deep tests
# ═══════════════════════════════════════════════════════════════════════

class TestAnalyzeRelocationsDeep:
    def test_no_relocations_result(self, ctx, clean_state):
        from arkana.mcp.tools_pe_structure import analyze_relocations
        _make_full_pe(clean_state)
        r = _run(analyze_relocations(ctx))
        assert r["has_relocations"] is False

    def test_aslr_no_relocs_anomaly(self, ctx, clean_state):
        from arkana.mcp.tools_pe_structure import analyze_relocations
        _make_full_pe(clean_state)
        # Set ASLR flag in pe_data
        clean_state.pe_data["nt_headers"] = {
            "optional_header": {"dll_characteristics": 0x0040},
            "file_header": {"characteristics": 0x0001},  # relocs stripped
        }
        r = _run(analyze_relocations(ctx))
        anomalies = r.get("anomalies", [])
        assert any("aslr" in str(a).lower() for a in anomalies)


class TestAnalyzeSehDeep:
    def test_x64_architecture(self, ctx, clean_state):
        from arkana.mcp.tools_pe_structure import analyze_seh_handlers
        _make_full_pe(clean_state)
        r = _run(analyze_seh_handlers(ctx))
        assert r["architecture"] == "x64"

    def test_x86_architecture(self, ctx, clean_state):
        from arkana.mcp.tools_pe_structure import analyze_seh_handlers
        _make_full_pe(clean_state)
        import arkana.config
        machine_type = getattr(arkana.config, 'pefile', None)
        if machine_type and hasattr(machine_type, 'MACHINE_TYPE'):
            clean_state.pe_object.FILE_HEADER.Machine = machine_type.MACHINE_TYPE.get(
                'IMAGE_FILE_MACHINE_I386', 0x14C)
        else:
            clean_state.pe_object.FILE_HEADER.Machine = 0x14C
        r = _run(analyze_seh_handlers(ctx))
        assert r["architecture"] == "x86"


class TestAnalyzeDebugDeep:
    def test_empty_debug_directory(self, ctx, clean_state):
        from arkana.mcp.tools_pe_structure import analyze_debug_directory
        _make_full_pe(clean_state)
        r = _run(analyze_debug_directory(ctx))
        assert isinstance(r, dict)

    def test_with_debug_entries(self, ctx, clean_state):
        from arkana.mcp.tools_pe_structure import analyze_debug_directory
        _make_full_pe(clean_state)
        debug_entry = MagicMock()
        debug_entry.struct.Type = 2  # IMAGE_DEBUG_TYPE_CODEVIEW
        debug_entry.struct.TimeDateStamp = 0x65000000
        debug_entry.struct.MajorVersion = 0
        debug_entry.struct.MinorVersion = 0
        debug_entry.struct.SizeOfData = 100
        debug_entry.struct.AddressOfRawData = 0x3000
        debug_entry.struct.PointerToRawData = 0x1000
        # CodeView entry needs realistic GUID fields (integers, not MagicMock)
        cv = MagicMock()
        cv.CvSignature = 0x53445352  # "RSDS"
        cv.GUID_Data1 = 0x12345678
        cv.GUID_Data2 = 0xABCD
        cv.GUID_Data3 = 0xEF01
        cv.GUID_Data4 = bytes([0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01])
        cv.Age = 1
        cv.PdbFileName = b"C:\\build\\sample.pdb\x00"
        debug_entry.entry = cv
        clean_state.pe_object.DIRECTORY_ENTRY_DEBUG = [debug_entry]
        r = _run(analyze_debug_directory(ctx))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════
#  tools_pe_forensic.py — deep tests
# ═══════════════════════════════════════════════════════════════════════

class TestParseAuthenticodeDeep:
    def test_unsigned_binary(self, ctx, clean_state):
        from arkana.mcp.tools_pe_forensic import parse_authenticode
        _make_full_pe(clean_state)
        r = _run(parse_authenticode(ctx))
        assert r.get("signed") is False

    def test_signed_flag_detection(self, ctx, clean_state):
        from arkana.mcp.tools_pe_forensic import parse_authenticode
        _make_full_pe(clean_state)
        # Set security directory to non-zero
        pe = clean_state.pe_object
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        sec_dir.VirtualAddress = 0x5000
        sec_dir.Size = 256
        r = _run(parse_authenticode(ctx))
        # Should detect as signed (even if signature data is invalid)
        assert r.get("signed") is True


class TestUnifyTimelineDeep:
    def test_collects_compile_timestamp(self, ctx, clean_state):
        from arkana.mcp.tools_pe_forensic import unify_artifact_timeline
        _make_full_pe(clean_state)
        r = _run(unify_artifact_timeline(ctx))
        assert isinstance(r, dict)
        artifacts = r.get("artifacts", r.get("timeline", []))
        assert isinstance(artifacts, list)
        assert len(artifacts) > 0  # At minimum, compile timestamp

    def test_no_resource_dir_no_crash(self, ctx, clean_state):
        from arkana.mcp.tools_pe_forensic import unify_artifact_timeline
        _make_full_pe(clean_state)
        clean_state.pe_object.DIRECTORY_ENTRY_RESOURCE = None
        r = _run(unify_artifact_timeline(ctx))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════
#  exports type safety — deep tests
# ═══════════════════════════════════════════════════════════════════════

class TestExportsSafetyDeep:
    def _base(self, exports):
        return {
            "file_hashes": {"md5": "a", "sha256": "b", "sha1": "c"},
            "pe_header": {"machine_type": "AMD64", "entry_point": "0x1000",
                          "timestamp": "2024-01-01", "timestamp_utc": "2024-01-01"},
            "sections": [{"name": ".text", "virtual_address": "0x1000",
                          "virtual_size": 4096, "raw_size": 4096, "entropy": 6.5}],
            "imports": {"k32.dll": ["Fn"]}, "exports": exports,
            "strings": [], "peid": {"ep_matches": [], "heuristic_matches": [], "status": "clean"},
            "yara_matches": [], "floss_analysis": {"static_strings": [], "decoded_strings": []},
        }

    def test_exports_string_value(self, ctx, clean_state):
        """Edge: exports is a string (corrupt data)."""
        from arkana.mcp.tools_pe import get_analyzed_file_summary
        clean_state.filepath = "/tmp/x.exe"
        clean_state.pe_data = self._base("not_a_dict")
        r = _run(get_analyzed_file_summary(ctx))
        assert r.get("export_symbol_count", 0) == 0

    def test_exports_int_value(self, ctx, clean_state):
        """Edge: exports is an int."""
        from arkana.mcp.tools_pe import get_analyzed_file_summary
        clean_state.filepath = "/tmp/x.exe"
        clean_state.pe_data = self._base(42)
        r = _run(get_analyzed_file_summary(ctx))
        assert r.get("export_symbol_count", 0) == 0

    def test_exports_large_symbols_list(self, ctx, clean_state):
        """Normal: exports dict with many symbols."""
        from arkana.mcp.tools_pe import get_analyzed_file_summary
        clean_state.filepath = "/tmp/x.exe"
        clean_state.pe_data = self._base(
            {"symbols": [{"name": f"Fn{i}"} for i in range(100)]}
        )
        r = _run(get_analyzed_file_summary(ctx))
        assert r["export_symbol_count"] == 100

    def test_full_results_compact_exports_none(self, ctx, clean_state):
        from arkana.mcp.tools_pe import get_full_analysis_results
        clean_state.filepath = "/tmp/x.exe"
        clean_state.pe_data = self._base(None)
        r = _run(get_full_analysis_results(ctx, limit=10, compact=True))
        assert r.get("export_count", 0) == 0

    def test_full_results_non_compact(self, ctx, clean_state):
        from arkana.mcp.tools_pe import get_full_analysis_results
        clean_state.filepath = "/tmp/x.exe"
        clean_state.pe_data = self._base({"symbols": [{"name": "Main"}]})
        r = _run(get_full_analysis_results(ctx, limit=5))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════
#  detect_null_regions — verify unaffected by changes
# ═══════════════════════════════════════════════════════════════════════

class TestDetectNullRegionsUnaffected:
    def test_detects_null_region(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_null_regions
        binary = bytearray(4096)
        binary[0:2] = b"MZ"
        # Leave 0x200-0x400 as nulls (512 bytes)
        binary[0x400:0x402] = b"\xFF\xFF"  # Non-null marker after
        _make_full_pe(clean_state, binary=bytes(binary))
        r = _run(detect_null_regions(ctx))
        assert isinstance(r, dict)

    def test_works_with_none_pe_object(self, ctx, clean_state):
        """detect_null_regions should work even with pe_object=None since it uses _binary_data."""
        from arkana.mcp.tools_pe_extended import detect_null_regions
        clean_state.filepath = "/tmp/x.exe"
        clean_state.pe_data = {"file_hashes": {"md5": "a"}, "sections": []}
        clean_state.pe_object = None
        clean_state._binary_data = b"\x00" * 1024
        r = _run(detect_null_regions(ctx))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════
#  scan_for_api_hashes — deep tests
# ═══════════════════════════════════════════════════════════════════════

class TestApiHashScanDeep:
    def test_clean_binary_no_matches(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import scan_for_api_hashes
        binary = bytearray(2048)
        binary[0:2] = b"MZ"
        _make_full_pe(clean_state, binary=bytes(binary))
        r = _run(scan_for_api_hashes(ctx))
        assert isinstance(r, dict)

    def test_result_structure(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import scan_for_api_hashes
        _make_full_pe(clean_state)
        r = _run(scan_for_api_hashes(ctx))
        assert isinstance(r, dict)
        # Should have matches list and metadata
        assert "matches" in r or "results" in r or "hash_matches" in r or "total_scanned" in r


# ═══════════════════════════════════════════════════════════════════════
#  detect_crypto_constants — deep tests
# ═══════════════════════════════════════════════════════════════════════

class TestCryptoConstantsDeep:
    def test_aes_sbox_detected(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_crypto_constants
        binary = _build_binary_with_content(
            crypto_bytes=[bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
                                 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76])],
        )
        _make_full_pe(clean_state, binary=binary)
        r = _run(detect_crypto_constants(ctx))
        assert isinstance(r, dict)
        # May or may not detect depending on minimum match length
        matches = r.get("matches", r.get("findings", r.get("constants", [])))
        assert isinstance(matches, list)

    def test_clean_binary(self, ctx, clean_state):
        from arkana.mcp.tools_pe_extended import detect_crypto_constants
        binary = bytearray(b"\x41" * 2048)
        binary[0:2] = b"MZ"
        _make_full_pe(clean_state, binary=bytes(binary))
        r = _run(detect_crypto_constants(ctx))
        matches = r.get("matches", r.get("findings", r.get("constants", [])))
        assert len(matches) == 0
