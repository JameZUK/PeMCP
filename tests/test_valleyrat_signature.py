"""Tests for ValleyRAT entry in malware signatures knowledge base."""

from pathlib import Path

import pytest
import yaml


_SIGNATURES_PATH = Path(__file__).resolve().parent.parent / "arkana" / "data" / "malware_signatures.yaml"


@pytest.fixture(scope="module")
def kb():
    """Load the malware signatures knowledge base."""
    with open(_SIGNATURES_PATH) as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="module")
def valleyrat(kb):
    """Find the ValleyRAT entry."""
    for family in kb.get("families", []):
        if family.get("family") == "ValleyRAT":
            return family
    pytest.fail("ValleyRAT not found in malware_signatures.yaml")


class TestValleyRATExists:
    """Verify ValleyRAT entry exists and is findable."""

    def test_entry_exists(self, valleyrat):
        assert valleyrat["family"] == "ValleyRAT"

    def test_findable_by_alias_silver_fox(self, kb):
        """Should be findable by 'Silver Fox RAT' alias."""
        for family in kb["families"]:
            if "Silver Fox RAT" in (family.get("aliases") or []):
                assert family["family"] == "ValleyRAT"
                return
        pytest.fail("Silver Fox RAT alias not found")

    def test_findable_by_alias_yinhu(self, kb):
        """Should be findable by 'Yinhu' alias."""
        for family in kb["families"]:
            if "Yinhu" in (family.get("aliases") or []):
                assert family["family"] == "ValleyRAT"
                return
        pytest.fail("Yinhu alias not found")

    def test_has_chinese_alias(self, valleyrat):
        """Should have the Chinese name alias."""
        aliases = valleyrat.get("aliases", [])
        assert any("\u94F6" in alias for alias in aliases), "Missing Chinese character alias"


class TestValleyRATSchema:
    """Verify ValleyRAT has required schema fields."""

    def test_has_description(self, valleyrat):
        assert valleyrat.get("description")
        assert len(valleyrat["description"]) > 20

    def test_has_config(self, valleyrat):
        config = valleyrat.get("config")
        assert config is not None
        assert config.get("encryption") == "custom_reversed_utf16le"
        assert config.get("structure") == "pipe_delimited_reversed_strings"
        assert config.get("parsed_fields")

    def test_has_network(self, valleyrat):
        network = valleyrat.get("network")
        assert network is not None
        assert "tcp" in network.get("protocols", [])
        assert "udp" in network.get("protocols", [])

    def test_has_typical_ports(self, valleyrat):
        ports = valleyrat["network"].get("typical_ports", [])
        assert 3323 in ports
        assert 6666 in ports

    def test_has_compilation(self, valleyrat):
        comp = valleyrat.get("compilation")
        assert comp is not None
        assert comp.get("compiler") == "msvc"
        assert comp.get("rich_header") is True

    def test_has_dll_loading(self, valleyrat):
        dll = valleyrat.get("dll_loading")
        assert dll is not None
        assert dll.get("technique") == "dll_sideloading"
        assert dll.get("sideload_host") == "tracerpt.exe"

    def test_has_yara_indicators(self, valleyrat):
        yara = valleyrat.get("yara_indicators")
        assert yara is not None
        strings = yara.get("string_patterns", [])
        assert "denglupeizhi" in strings
        assert "IpDates_info" in strings

    def test_has_mitre_attack(self, valleyrat):
        mitre = valleyrat.get("mitre_attack", [])
        assert len(mitre) >= 5
        assert "T1055.012" in mitre  # Process Hollowing
        assert "T1095" in mitre  # Non-Application Layer Protocol
        assert "T1574.002" in mitre  # DLL Side-Loading

    def test_has_references(self, valleyrat):
        refs = valleyrat.get("references", [])
        assert len(refs) >= 2
        assert any("fortinet" in r.get("url", "").lower() for r in refs)

    def test_has_commands(self, valleyrat):
        cmds = valleyrat.get("commands")
        assert cmds is not None
        assert len(cmds.get("known_names", [])) >= 5


class TestValleyRATFindFamily:
    """Test using the actual _find_family function."""

    def setup_method(self):
        # Clear cached KB to ensure fresh load
        import arkana.mcp.tools_malware_identify as mod
        mod._kb_cache = None

    def test_find_by_name(self):
        from arkana.mcp.tools_malware_identify import _find_family
        entry = _find_family("ValleyRAT")
        assert entry is not None
        assert entry["family"] == "ValleyRAT"

    def test_find_by_name_case_insensitive(self):
        from arkana.mcp.tools_malware_identify import _find_family
        entry = _find_family("valleyrat")
        assert entry is not None

    def test_find_by_alias(self):
        from arkana.mcp.tools_malware_identify import _find_family
        entry = _find_family("Silver Fox RAT")
        assert entry is not None
        assert entry["family"] == "ValleyRAT"

    def test_find_by_alias_yinhu(self):
        from arkana.mcp.tools_malware_identify import _find_family
        entry = _find_family("Yinhu")
        assert entry is not None
        assert entry["family"] == "ValleyRAT"
