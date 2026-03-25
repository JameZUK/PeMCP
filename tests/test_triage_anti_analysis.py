"""Unit tests for VM indicator detection and anti-debug instruction scanning in tools_triage.py."""
import struct
import pytest

pytest.importorskip("pefile", reason="pefile not installed")

from unittest.mock import patch, MagicMock, PropertyMock
from arkana.state import AnalyzerState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pe_with_raw_data(raw_bytes: bytes):
    """Create a mock PE object with __data__ containing raw_bytes."""
    pe = MagicMock()
    pe.__data__ = raw_bytes
    pe.sections = []
    return pe


def _make_section(name: str, data: bytes, executable: bool = True):
    """Create a mock PE section with the given data and characteristics."""
    section = MagicMock()
    section.Name = name.encode("ascii").ljust(8, b"\x00")
    section.get_data.return_value = data
    section.VirtualAddress = 0x1000
    # IMAGE_SCN_MEM_EXECUTE = 0x20000000
    section.Characteristics = 0x60000020 if executable else 0x40000040
    return section


def _make_pe_with_sections(sections, image_base=0x400000):
    """Create a mock PE object with sections and OPTIONAL_HEADER."""
    pe = MagicMock()
    pe.sections = sections
    pe.OPTIONAL_HEADER = MagicMock()
    pe.OPTIONAL_HEADER.ImageBase = image_base
    pe.__data__ = b"\x00" * 100  # minimal raw data
    return pe


# ---------------------------------------------------------------------------
# VM Indicator String Detection
# ---------------------------------------------------------------------------

class TestTriageVmIndicatorStrings:
    """Tests for _triage_vm_indicator_strings."""

    def _call(self, pe_object, indicator_limit=100):
        mock_state = AnalyzerState()
        mock_state.pe_object = pe_object
        with patch("arkana.mcp.tools_triage.state", mock_state):
            from arkana.mcp.tools_triage import _triage_vm_indicator_strings
            return _triage_vm_indicator_strings(indicator_limit)

    def test_vmware_detected(self):
        raw = b"\x00" * 100 + b"VMwareVMware" + b"\x00" * 100
        pe = _make_pe_with_raw_data(raw)
        result, risk = self._call(pe)
        assert result["has_vm_detection"] is True
        assert result["count"] >= 1
        targets = [ind["target"] for ind in result["vm_indicators"]]
        assert "VMware" in targets

    def test_virtualbox_detected(self):
        raw = b"\x00" * 50 + b"VBoxGuest" + b"\x00" * 50
        pe = _make_pe_with_raw_data(raw)
        result, risk = self._call(pe)
        assert result["has_vm_detection"] is True
        targets = [ind["target"] for ind in result["vm_indicators"]]
        assert "VirtualBox" in targets

    def test_multiple_indicators(self):
        raw = (b"\x00" * 20 + b"VMwareVMware" +
               b"\x00" * 20 + b"VBoxGuest" +
               b"\x00" * 20 + b"KVMKVMKVM" +
               b"\x00" * 20)
        pe = _make_pe_with_raw_data(raw)
        result, risk = self._call(pe)
        assert result["count"] >= 3
        assert result["has_vm_detection"] is True
        # Multiple unique indicators should have hypervisor breakdown
        assert "hypervisor_breakdown" in result

    def test_no_indicators_on_clean_data(self):
        raw = b"This is clean binary data with no VM strings" + b"\x00" * 200
        pe = _make_pe_with_raw_data(raw)
        result, risk = self._call(pe)
        assert result["has_vm_detection"] is False
        assert result["count"] == 0
        assert result["vm_indicators"] == []
        assert risk == 0

    def test_risk_score_for_many_indicators(self):
        """5+ indicators should yield risk score 3."""
        raw = (b"\x00" * 10 + b"VMwareVMware" +
               b"\x00" * 10 + b"VBoxGuest" +
               b"\x00" * 10 + b"KVMKVMKVM" +
               b"\x00" * 10 + b"SbieDll" +
               b"\x00" * 10 + b"cuckoomon" +
               b"\x00" * 10)
        pe = _make_pe_with_raw_data(raw)
        result, risk = self._call(pe)
        assert result["count"] >= 5
        assert risk == 3

    def test_risk_score_for_few_indicators(self):
        """3-4 indicators should yield risk score 2."""
        raw = (b"\x00" * 10 + b"VMwareVMware" +
               b"\x00" * 10 + b"VBoxGuest" +
               b"\x00" * 10 + b"KVMKVMKVM" +
               b"\x00" * 10)
        pe = _make_pe_with_raw_data(raw)
        result, risk = self._call(pe)
        assert result["count"] >= 3
        assert risk == 2

    def test_risk_score_for_single_indicator(self):
        """1-2 indicators should yield risk score 1."""
        raw = b"\x00" * 50 + b"VMwareVMware" + b"\x00" * 50
        pe = _make_pe_with_raw_data(raw)
        result, risk = self._call(pe)
        assert result["count"] >= 1
        assert risk == 1

    def test_indicator_limit_enforced(self):
        raw = (b"\x00" * 10 + b"VMwareVMware" +
               b"\x00" * 10 + b"VBoxGuest" +
               b"\x00" * 10 + b"KVMKVMKVM" +
               b"\x00" * 10 + b"SbieDll" +
               b"\x00" * 10 + b"cuckoomon" +
               b"\x00" * 10)
        pe = _make_pe_with_raw_data(raw)
        result, _ = self._call(pe, indicator_limit=2)
        assert len(result["vm_indicators"]) <= 2

    def test_deduplicated(self):
        """Same indicator appearing twice should be counted once."""
        raw = b"VMwareVMware" + b"\x00" * 10 + b"VMwareVMware"
        pe = _make_pe_with_raw_data(raw)
        result, _ = self._call(pe)
        vmware_entries = [ind for ind in result["vm_indicators"]
                          if "VMwareVMware" in ind["indicator"]]
        assert len(vmware_entries) == 1

    def test_no_pe_object(self):
        result, risk = self._call(None)
        assert result["has_vm_detection"] is False
        assert result["count"] == 0
        assert risk == 0

    def test_pe_object_no_data_attribute(self):
        pe = MagicMock(spec=[])  # No __data__
        result, risk = self._call(pe)
        assert result["has_vm_detection"] is False
        assert risk == 0

    def test_hypervisor_breakdown_populated(self):
        raw = (b"\x00" * 10 + b"VMwareVMware" +
               b"\x00" * 10 + b"vmci.sys" +
               b"\x00" * 10)
        pe = _make_pe_with_raw_data(raw)
        result, _ = self._call(pe)
        assert "hypervisor_breakdown" in result
        assert "VMware" in result["hypervisor_breakdown"]
        assert len(result["hypervisor_breakdown"]["VMware"]) >= 1


# ---------------------------------------------------------------------------
# Anti-Debug Instruction Detection
# ---------------------------------------------------------------------------

class TestTriageAntiDebugInstructions:
    """Tests for _triage_anti_debug_instructions."""

    def _call(self, pe_object, indicator_limit=100):
        mock_state = AnalyzerState()
        mock_state.pe_object = pe_object
        with patch("arkana.mcp.tools_triage.state", mock_state):
            from arkana.mcp.tools_triage import _triage_anti_debug_instructions
            return _triage_anti_debug_instructions(indicator_limit)

    def test_rdtsc_detected(self):
        """RDTSC (0F 31) in executable section should be found."""
        data = b"\x90" * 100 + b"\x0f\x31" + b"\x90" * 100
        section = _make_section(".text", data, executable=True)
        pe = _make_pe_with_sections([section])
        result, risk = self._call(pe)
        assert result["has_anti_debug_instructions"] is True
        assert result["count"] >= 1
        mnemonics = [f["instruction"] for f in result["anti_debug_instructions"]]
        assert "RDTSC" in mnemonics

    def test_cpuid_detected(self):
        """CPUID (0F A2) in executable section should be found."""
        data = b"\x90" * 50 + b"\x0f\xa2" + b"\x90" * 50
        section = _make_section(".text", data, executable=True)
        pe = _make_pe_with_sections([section])
        result, risk = self._call(pe)
        assert result["has_anti_debug_instructions"] is True
        mnemonics = [f["instruction"] for f in result["anti_debug_instructions"]]
        assert "CPUID" in mnemonics

    def test_int_2d_detected(self):
        """INT 2Dh (CD 2D) should be detected."""
        data = b"\x90" * 50 + b"\xcd\x2d" + b"\x90" * 50
        section = _make_section(".text", data, executable=True)
        pe = _make_pe_with_sections([section])
        result, risk = self._call(pe)
        assert result["has_anti_debug_instructions"] is True
        mnemonics = [f["instruction"] for f in result["anti_debug_instructions"]]
        assert "INT 2Dh" in mnemonics

    def test_sidt_detected(self):
        """SIDT (0F 01 0D) should be detected."""
        data = b"\x90" * 50 + b"\x0f\x01\x0d" + b"\x90" * 50
        section = _make_section(".text", data, executable=True)
        pe = _make_pe_with_sections([section])
        result, risk = self._call(pe)
        assert result["has_anti_debug_instructions"] is True
        mnemonics = [f["instruction"] for f in result["anti_debug_instructions"]]
        assert "SIDT" in mnemonics

    def test_non_executable_section_skipped(self):
        """Sections without IMAGE_SCN_MEM_EXECUTE should be ignored."""
        data = b"\x90" * 50 + b"\x0f\x31" + b"\x90" * 50  # RDTSC
        section = _make_section(".rdata", data, executable=False)
        pe = _make_pe_with_sections([section])
        result, risk = self._call(pe)
        assert result["has_anti_debug_instructions"] is False
        assert result["count"] == 0

    def test_empty_section_no_crash(self):
        """Empty executable section should not crash."""
        section = _make_section(".text", b"", executable=True)
        pe = _make_pe_with_sections([section])
        result, risk = self._call(pe)
        assert result["has_anti_debug_instructions"] is False
        assert result["count"] == 0

    def test_no_pe_object(self):
        result, risk = self._call(None)
        assert result["has_anti_debug_instructions"] is False
        assert result["count"] == 0
        assert risk == 0

    def test_multiple_patterns_in_same_section(self):
        """Multiple different anti-debug patterns in one section."""
        data = (b"\x90" * 10 + b"\x0f\x31" +  # RDTSC
                b"\x90" * 10 + b"\x0f\xa2" +   # CPUID
                b"\x90" * 10 + b"\xcd\x2d" +   # INT 2Dh
                b"\x90" * 10)
        section = _make_section(".text", data, executable=True)
        pe = _make_pe_with_sections([section])
        result, risk = self._call(pe)
        assert result["count"] >= 3
        mnemonics = [f["instruction"] for f in result["anti_debug_instructions"]]
        assert "RDTSC" in mnemonics
        assert "CPUID" in mnemonics
        assert "INT 2Dh" in mnemonics

    def test_multiple_occurrences_tracked(self):
        """Multiple RDTSC in one section should show count > 1."""
        data = (b"\x0f\x31" + b"\x90" * 10 +
                b"\x0f\x31" + b"\x90" * 10 +
                b"\x0f\x31")
        section = _make_section(".text", data, executable=True)
        pe = _make_pe_with_sections([section])
        result, risk = self._call(pe)
        rdtsc_findings = [f for f in result["anti_debug_instructions"]
                          if f["instruction"] == "RDTSC"]
        assert len(rdtsc_findings) == 1
        assert rdtsc_findings[0]["count"] == 3

    def test_addresses_include_image_base(self):
        """Reported addresses should include image base + section RVA."""
        data = b"\x0f\x31"  # RDTSC at offset 0
        section = _make_section(".text", data, executable=True)
        pe = _make_pe_with_sections([section], image_base=0x400000)
        result, _ = self._call(pe)
        addrs = result["anti_debug_instructions"][0]["addresses"]
        # image_base (0x400000) + VirtualAddress (0x1000) + offset (0) = 0x401000
        assert addrs[0] == hex(0x400000 + 0x1000 + 0)

    def test_risk_score_high_severity(self):
        """Two high-severity findings (CPUID, INT 2Dh) should give risk 3."""
        data = (b"\x90" * 10 + b"\x0f\xa2" +   # CPUID (high)
                b"\x90" * 10 + b"\xcd\x2d" +   # INT 2Dh (high)
                b"\x90" * 10)
        section = _make_section(".text", data, executable=True)
        pe = _make_pe_with_sections([section])
        result, risk = self._call(pe)
        assert risk == 3

    def test_risk_score_medium_only(self):
        """Only medium-severity findings should give risk 1."""
        data = b"\x90" * 10 + b"\x0f\x31" + b"\x90" * 10  # RDTSC (medium)
        section = _make_section(".text", data, executable=True)
        pe = _make_pe_with_sections([section])
        result, risk = self._call(pe)
        assert risk == 1

    def test_indicator_limit_caps_results(self):
        """The indicator_limit should cap the returned findings."""
        data = (b"\x90" * 10 + b"\x0f\x31" +   # RDTSC
                b"\x90" * 10 + b"\x0f\xa2" +   # CPUID
                b"\x90" * 10 + b"\xcd\x2d" +   # INT 2Dh
                b"\x90" * 10 + b"\x0f\x01\x0d" +  # SIDT
                b"\x90" * 10)
        section = _make_section(".text", data, executable=True)
        pe = _make_pe_with_sections([section])
        result, _ = self._call(pe, indicator_limit=2)
        assert len(result["anti_debug_instructions"]) <= 2

    def test_section_name_in_findings(self):
        """Each finding should include the section name."""
        data = b"\x90" * 10 + b"\x0f\x31" + b"\x90" * 10
        section = _make_section(".text", data, executable=True)
        pe = _make_pe_with_sections([section])
        result, _ = self._call(pe)
        assert result["anti_debug_instructions"][0]["section"] == ".text"

    def test_pe_without_sections_attribute(self):
        """PE object without sections attribute should return empty."""
        pe = MagicMock(spec=[])  # No sections attr
        result, risk = self._call(pe)
        assert result["has_anti_debug_instructions"] is False
        assert risk == 0
