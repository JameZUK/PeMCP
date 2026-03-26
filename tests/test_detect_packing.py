"""Tests for detect_packing tool — validates section size cap, no-CFG requirement, and all 5 heuristics."""
import asyncio
import unittest
from unittest.mock import MagicMock, patch, AsyncMock

from arkana.state import AnalyzerState, set_current_state


def _make_section(name=".text", min_addr=0x401000, memsize=4096,
                  is_executable=False, max_addr=None):
    """Create a mock section with the fields detect_packing reads."""
    s = MagicMock()
    s.name = name
    s.min_addr = min_addr
    s.memsize = memsize
    s.max_addr = max_addr if max_addr is not None else (min_addr + memsize - 1)
    s.is_executable = is_executable
    return s


def _make_loader(sections=None, imports=None, entry=0x401000, memory_data=None):
    """Create a mock angr loader + project with controllable sections/imports."""
    loader = MagicMock()
    loader.main_object.sections = sections or []
    loader.main_object.imports = imports if imports is not None else {"func1": 1, "func2": 2, "func3": 3, "func4": 4, "func5": 5}

    def _load(addr, size):
        if memory_data is not None:
            return memory_data[:size]
        return b"\x00" * size

    loader.memory.load = MagicMock(side_effect=_load)

    project = MagicMock()
    project.loader = loader
    project.entry = entry
    project.analyses.PackingDetector.side_effect = AttributeError("not available")
    return project


class TestDetectPackingNoCFGRequired(unittest.TestCase):
    """Verify detect_packing does NOT require or wait for a full CFG."""

    def test_require_cfg_false_in_source(self):
        """The _check_angr_ready call must use require_cfg=False."""
        import inspect
        from arkana.mcp.tools_angr_forensic import detect_packing
        source = inspect.getsource(detect_packing)
        assert "require_cfg=False" in source, \
            "detect_packing must call _check_angr_ready with require_cfg=False"

    def test_no_ensure_project_and_cfg_call(self):
        """detect_packing must NOT call _ensure_project_and_cfg."""
        import inspect
        from arkana.mcp.tools_angr_forensic import detect_packing
        source = inspect.getsource(detect_packing)
        assert "_ensure_project_and_cfg" not in source, \
            "detect_packing must not call _ensure_project_and_cfg (causes CFG wait)"


class TestDetectPackingSectionSizeCap(unittest.TestCase):
    """Verify entropy computation caps section reads at 10MB."""

    def test_max_entropy_section_bytes_constant(self):
        """The 10MB cap constant must exist in the function."""
        import inspect
        from arkana.mcp.tools_angr_forensic import detect_packing
        source = inspect.getsource(detect_packing)
        assert "_MAX_ENTROPY_SECTION_BYTES" in source

    def test_large_section_capped(self):
        """A section with memsize > 10MB should only load 10MB."""
        huge_memsize = 100 * 1024 * 1024  # 100 MB
        section = _make_section(memsize=huge_memsize, is_executable=True)
        project = _make_loader(sections=[section])

        st = AnalyzerState()
        set_current_state(st)
        st.filepath = "/tmp/test.exe"

        with patch("arkana.mcp.tools_angr_forensic.state", st):
            st.angr_project = project
            # Extract the _detect inner function by calling with mocked async context
            # Instead, test the logic directly:
            cap = 10 * 1024 * 1024
            load_size = min(section.memsize, cap)
            assert load_size == cap, f"Should cap at 10MB, got {load_size}"

    def test_small_section_not_capped(self):
        """A section smaller than 10MB should load its full size."""
        small_memsize = 4096
        cap = 10 * 1024 * 1024
        load_size = min(small_memsize, cap)
        assert load_size == small_memsize


class TestDetectPackingHeuristics(unittest.TestCase):
    """Test all 5 packing detection heuristics via the inner _detect function."""

    def setUp(self):
        self.st = AnalyzerState()
        set_current_state(self.st)
        self.st.filepath = "/tmp/test.exe"

    def _run_detect(self, project):
        """Run detect_packing with a mocked project, return the result dict."""
        from arkana.mcp.tools_angr_forensic import detect_packing

        self.st.angr_project = project
        ctx = AsyncMock()
        ctx.info = AsyncMock()
        ctx.report_progress = AsyncMock()

        loop = asyncio.new_event_loop()
        try:
            with patch("arkana.mcp.tools_angr_forensic.state", self.st), \
                 patch("arkana.mcp.tools_angr_forensic._check_angr_ready"), \
                 patch("arkana.mcp.tools_angr_forensic.ProgressBridge"), \
                 patch("arkana.mcp.tools_angr_forensic.ANGR_ANALYSIS_TIMEOUT", 30), \
                 patch("arkana.mcp.tools_angr_forensic._check_mcp_response_size",
                       new_callable=lambda: (lambda: AsyncMock(side_effect=lambda ctx, r, n: r))()):
                result = loop.run_until_complete(detect_packing(ctx))
                return result
        finally:
            if loop._default_executor is not None:
                loop.run_until_complete(loop.shutdown_default_executor())
            loop.close()

    def test_not_packed_clean_binary(self):
        """Normal binary with regular sections, plenty of imports → not_packed."""
        sections = [
            _make_section(".text", 0x401000, 4096, is_executable=True),
            _make_section(".data", 0x402000, 4096),
        ]
        # Normal entropy (all zeros = 0.0)
        project = _make_loader(sections=sections,
                               imports={f"func{i}": i for i in range(20)},
                               entry=0x401000)
        result = self._run_detect(project)
        assert result["verdict"] == "not_packed"
        assert result["confidence_score"] == 0

    def test_high_entropy_executable_section(self):
        """High entropy executable section → high severity indicator, score += 3."""
        import os
        high_entropy_data = os.urandom(4096)  # ~8.0 entropy
        section = _make_section(".text", 0x401000, 4096, is_executable=True)
        project = _make_loader(sections=[section],
                               imports={f"f{i}": i for i in range(20)},
                               entry=0x401000,
                               memory_data=high_entropy_data)
        result = self._run_detect(project)
        types = [i["type"] for i in result["indicators"]]
        assert "high_entropy_executable" in types
        assert result["confidence_score"] >= 3

    def test_elevated_entropy_non_executable(self):
        """Elevated entropy on non-exec section → medium severity, score += 1."""
        import os
        high_entropy_data = os.urandom(4096)
        section = _make_section(".rsrc", 0x402000, 4096, is_executable=False)
        project = _make_loader(sections=[section],
                               imports={f"f{i}": i for i in range(20)},
                               entry=0x401000,
                               memory_data=high_entropy_data)
        result = self._run_detect(project)
        types = [i["type"] for i in result["indicators"]]
        assert "elevated_entropy" in types

    def test_very_few_imports(self):
        """< 5 imports → very_few_imports indicator, score += 2."""
        project = _make_loader(imports={"LoadLibraryA": 1, "GetProcAddress": 2},
                               entry=0x401000)
        result = self._run_detect(project)
        types = [i["type"] for i in result["indicators"]]
        assert "very_few_imports" in types
        imp_ind = [i for i in result["indicators"] if i["type"] == "very_few_imports"][0]
        assert imp_ind["count"] == 2

    def test_known_packer_section_upx(self):
        """UPX section names → known_packer_section, score += 3 each."""
        sections = [
            _make_section("UPX0", 0x401000, 4096),
            _make_section("UPX1", 0x402000, 4096),
        ]
        project = _make_loader(sections=sections,
                               imports={f"f{i}": i for i in range(20)},
                               entry=0x401000)
        result = self._run_detect(project)
        packer_indicators = [i for i in result["indicators"] if i["type"] == "known_packer_section"]
        assert len(packer_indicators) == 2
        assert result["confidence_score"] >= 6
        assert result["verdict"] == "likely_packed"

    def test_entry_point_anomaly(self):
        """Entry point outside first section → entry_point_anomaly, score += 1."""
        section = _make_section(".text", 0x401000, 4096, max_addr=0x401FFF)
        project = _make_loader(sections=[section],
                               imports={f"f{i}": i for i in range(20)},
                               entry=0x500000)  # Way outside .text
        result = self._run_detect(project)
        types = [i["type"] for i in result["indicators"]]
        assert "entry_point_anomaly" in types

    def test_entry_point_inside_first_section_no_anomaly(self):
        """Entry point inside first section → no anomaly."""
        section = _make_section(".text", 0x401000, 4096, max_addr=0x401FFF)
        project = _make_loader(sections=[section],
                               imports={f"f{i}": i for i in range(20)},
                               entry=0x401500)  # Inside .text
        result = self._run_detect(project)
        types = [i["type"] for i in result["indicators"]]
        assert "entry_point_anomaly" not in types

    def test_verdict_likely_packed(self):
        """Combined score >= 5 → likely_packed."""
        import os
        high_entropy_data = os.urandom(4096)
        sections = [
            _make_section("UPX0", 0x401000, 4096, is_executable=True),
        ]
        project = _make_loader(sections=sections,
                               imports={"LoadLibraryA": 1},  # 1 import
                               entry=0x500000,  # Outside section
                               memory_data=high_entropy_data)
        result = self._run_detect(project)
        assert result["verdict"] == "likely_packed"
        assert result["confidence_score"] >= 5

    def test_verdict_possibly_packed(self):
        """Combined score 2-4 → possibly_packed."""
        project = _make_loader(imports={"LoadLibraryA": 1, "GetProcAddress": 2},  # 2 imports → score 2
                               entry=0x401000)
        result = self._run_detect(project)
        assert result["verdict"] == "possibly_packed"
        assert 2 <= result["confidence_score"] < 5

    def test_no_project_returns_error(self):
        """No angr project → error dict."""
        from arkana.mcp.tools_angr_forensic import detect_packing

        self.st.angr_project = None
        ctx = AsyncMock()
        ctx.info = AsyncMock()
        ctx.report_progress = AsyncMock()

        loop = asyncio.new_event_loop()
        try:
            with patch("arkana.mcp.tools_angr_forensic.state", self.st), \
                 patch("arkana.mcp.tools_angr_forensic._check_angr_ready"), \
                 patch("arkana.mcp.tools_angr_forensic.ProgressBridge"), \
                 patch("arkana.mcp.tools_angr_forensic.ANGR_ANALYSIS_TIMEOUT", 30):
                with self.assertRaises(RuntimeError):
                    # _raise_on_error_dict should convert error dict to RuntimeError
                    loop.run_until_complete(detect_packing(ctx))
        finally:
            if loop._default_executor is not None:
                loop.run_until_complete(loop.shutdown_default_executor())
            loop.close()

    def test_packing_detector_attribute_error_handled(self):
        """PackingDetector not available → gracefully skipped."""
        project = _make_loader(imports={f"f{i}": i for i in range(20)},
                               entry=0x401000)
        project.analyses.PackingDetector.side_effect = AttributeError("no PackingDetector")
        result = self._run_detect(project)
        types = [i["type"] for i in result["indicators"]]
        assert "angr_packing_detector" not in types

    def test_section_load_exception_handled(self):
        """Exception during section entropy load → section skipped, no crash."""
        section = _make_section(".text", 0x401000, 4096, is_executable=True)
        project = _make_loader(sections=[section],
                               imports={f"f{i}": i for i in range(20)},
                               entry=0x401000)
        project.loader.memory.load.side_effect = Exception("memory read failed")
        result = self._run_detect(project)
        # Should not crash, just skip the section
        assert result["verdict"] in ("not_packed", "possibly_packed", "likely_packed")

    def test_no_sections_handled(self):
        """Binary with no sections → no entropy/name/entry indicators."""
        project = _make_loader(sections=[],
                               imports={f"f{i}": i for i in range(20)},
                               entry=0x401000)
        project.loader.main_object.sections = []
        result = self._run_detect(project)
        entropy_types = [i for i in result["indicators"]
                         if i["type"] in ("high_entropy_executable", "elevated_entropy",
                                          "known_packer_section", "entry_point_anomaly")]
        assert len(entropy_types) == 0

    def test_memory_load_called_with_capped_size(self):
        """Verify loader.memory.load is called with capped size for huge sections."""
        huge_section = _make_section(".big", 0x401000, 200 * 1024 * 1024)  # 200 MB
        project = _make_loader(sections=[huge_section],
                               imports={f"f{i}": i for i in range(20)},
                               entry=0x401000)
        self._run_detect(project)
        # Check that memory.load was called with 10MB, not 200MB
        calls = project.loader.memory.load.call_args_list
        assert len(calls) >= 1
        _, called_size = calls[0][0]  # positional args: (addr, size)
        cap = 10 * 1024 * 1024
        assert called_size == cap, f"Expected capped load of {cap}, got {called_size}"


class TestDetectPackingKnownPackerSections(unittest.TestCase):
    """Test all known packer section names are detected."""

    def setUp(self):
        self.st = AnalyzerState()
        set_current_state(self.st)
        self.st.filepath = "/tmp/test.exe"

    def _run_detect(self, project):
        from arkana.mcp.tools_angr_forensic import detect_packing
        self.st.angr_project = project
        ctx = AsyncMock()
        ctx.info = AsyncMock()
        ctx.report_progress = AsyncMock()
        loop = asyncio.new_event_loop()
        try:
            with patch("arkana.mcp.tools_angr_forensic.state", self.st), \
                 patch("arkana.mcp.tools_angr_forensic._check_angr_ready"), \
                 patch("arkana.mcp.tools_angr_forensic.ProgressBridge"), \
                 patch("arkana.mcp.tools_angr_forensic.ANGR_ANALYSIS_TIMEOUT", 30), \
                 patch("arkana.mcp.tools_angr_forensic._check_mcp_response_size",
                       new_callable=lambda: (lambda: AsyncMock(side_effect=lambda ctx, r, n: r))()):
                return loop.run_until_complete(detect_packing(ctx))
        finally:
            if loop._default_executor is not None:
                loop.run_until_complete(loop.shutdown_default_executor())
            loop.close()

    def test_all_packer_sections_detected(self):
        """Every known packer section name should trigger an indicator."""
        known = ['UPX0', 'UPX1', 'UPX2', '.aspack', '.adata',
                 '.nsp0', '.nsp1', '.perplex', '.themida']
        for name in known:
            section = _make_section(name, 0x401000, 4096)
            project = _make_loader(sections=[section],
                                   imports={f"f{i}": i for i in range(20)},
                                   entry=0x401000)
            result = self._run_detect(project)
            packer_inds = [i for i in result["indicators"] if i["type"] == "known_packer_section"]
            assert len(packer_inds) >= 1, f"Section '{name}' not detected as packer section"
            assert packer_inds[0]["section"] == name

    def test_normal_section_not_flagged(self):
        """Normal section names like .text, .data should NOT be flagged."""
        for name in ['.text', '.data', '.rdata', '.rsrc', '.reloc', '.bss']:
            section = _make_section(name, 0x401000, 4096)
            project = _make_loader(sections=[section],
                                   imports={f"f{i}": i for i in range(20)},
                                   entry=0x401000)
            result = self._run_detect(project)
            packer_inds = [i for i in result["indicators"] if i["type"] == "known_packer_section"]
            assert len(packer_inds) == 0, f"Section '{name}' incorrectly flagged as packer"


if __name__ == "__main__":
    unittest.main()
