"""Tests for output_path parameter across extraction/transform/report tools.

Verifies that:
1. All 18 tools accept the output_path parameter
2. The _write_output_and_register_artifact import is available in each module
3. Parameter signatures are correct
"""
import inspect
import unittest


class TestOutputPathParameterExists(unittest.TestCase):
    """Verify all 18 tools have output_path in their signature."""

    def _check_output_path_param(self, func, tool_name):
        """Assert func has output_path: Optional[str] = None parameter."""
        # Get the unwrapped function (past tool_decorator)
        inner = getattr(func, "__wrapped__", func)
        sig = inspect.signature(inner)
        self.assertIn(
            "output_path", sig.parameters,
            f"{tool_name} is missing output_path parameter",
        )
        param = sig.parameters["output_path"]
        self.assertEqual(
            param.default, None,
            f"{tool_name}.output_path should default to None",
        )

    # -- Group A: Refinery transform tools --

    def test_refinery_codec_has_output_path(self):
        from arkana.mcp.tools_refinery import refinery_codec
        self._check_output_path_param(refinery_codec, "refinery_codec")

    def test_refinery_decrypt_has_output_path(self):
        from arkana.mcp.tools_refinery import refinery_decrypt
        self._check_output_path_param(refinery_decrypt, "refinery_decrypt")

    def test_refinery_decompress_has_output_path(self):
        from arkana.mcp.tools_refinery import refinery_decompress
        self._check_output_path_param(refinery_decompress, "refinery_decompress")

    def test_refinery_auto_decrypt_has_output_path(self):
        from arkana.mcp.tools_refinery_advanced import refinery_auto_decrypt
        self._check_output_path_param(refinery_auto_decrypt, "refinery_auto_decrypt")

    def test_refinery_decompile_has_output_path(self):
        from arkana.mcp.tools_refinery_advanced import refinery_decompile
        self._check_output_path_param(refinery_decompile, "refinery_decompile")

    # -- Group B: Multi-file extraction --

    def test_refinery_extract_has_output_path(self):
        from arkana.mcp.tools_refinery_extract import refinery_extract
        self._check_output_path_param(refinery_extract, "refinery_extract")

    def test_refinery_dotnet_has_output_path(self):
        from arkana.mcp.tools_refinery_dotnet import refinery_dotnet
        self._check_output_path_param(refinery_dotnet, "refinery_dotnet")

    def test_extract_steganography_has_output_path(self):
        from arkana.mcp.tools_payload import extract_steganography
        self._check_output_path_param(extract_steganography, "extract_steganography")

    def test_parse_custom_container_has_output_path(self):
        from arkana.mcp.tools_payload import parse_custom_container
        self._check_output_path_param(parse_custom_container, "parse_custom_container")

    # -- Group C: Text/report tools --

    def test_generate_analysis_report_has_output_path(self):
        from arkana.mcp.tools_workflow import generate_analysis_report
        self._check_output_path_param(generate_analysis_report, "generate_analysis_report")

    def test_generate_yara_rule_has_output_path(self):
        from arkana.mcp.tools_pe_forensic import generate_yara_rule
        self._check_output_path_param(generate_yara_rule, "generate_yara_rule")

    def test_generate_sigma_rule_has_output_path(self):
        from arkana.mcp.tools_threat_intel import generate_sigma_rule
        self._check_output_path_param(generate_sigma_rule, "generate_sigma_rule")

    def test_map_mitre_attack_has_output_path(self):
        from arkana.mcp.tools_threat_intel import map_mitre_attack
        self._check_output_path_param(map_mitre_attack, "map_mitre_attack")

    def test_get_iocs_structured_has_output_path(self):
        from arkana.mcp.tools_ioc import get_iocs_structured
        self._check_output_path_param(get_iocs_structured, "get_iocs_structured")

    def test_extract_config_automated_has_output_path(self):
        from arkana.mcp.tools_payload import extract_config_automated
        self._check_output_path_param(extract_config_automated, "extract_config_automated")

    def test_extract_config_for_family_has_output_path(self):
        from arkana.mcp.tools_payload import extract_config_for_family
        self._check_output_path_param(extract_config_for_family, "extract_config_for_family")

    # -- Group D: Special cases --

    def test_reconstruct_pe_from_dump_has_output_path(self):
        from arkana.mcp.tools_unpack import reconstruct_pe_from_dump
        self._check_output_path_param(reconstruct_pe_from_dump, "reconstruct_pe_from_dump")

    def test_brute_force_simple_crypto_has_output_path(self):
        from arkana.mcp.tools_crypto import brute_force_simple_crypto
        self._check_output_path_param(brute_force_simple_crypto, "brute_force_simple_crypto")


class TestWriteHelperImported(unittest.TestCase):
    """Verify _write_output_and_register_artifact is importable in each module."""

    def test_tools_refinery_import(self):
        from arkana.mcp import tools_refinery
        self.assertTrue(hasattr(tools_refinery, '_write_output_and_register_artifact'))

    def test_tools_refinery_advanced_import(self):
        from arkana.mcp import tools_refinery_advanced
        self.assertTrue(hasattr(tools_refinery_advanced, '_write_output_and_register_artifact'))

    def test_tools_refinery_extract_import(self):
        from arkana.mcp import tools_refinery_extract
        self.assertTrue(hasattr(tools_refinery_extract, '_write_output_and_register_artifact'))

    def test_tools_refinery_dotnet_import(self):
        from arkana.mcp import tools_refinery_dotnet
        self.assertTrue(hasattr(tools_refinery_dotnet, '_write_output_and_register_artifact'))

    def test_tools_unpack_import(self):
        from arkana.mcp import tools_unpack
        self.assertTrue(hasattr(tools_unpack, '_write_output_and_register_artifact'))

    def test_tools_workflow_import(self):
        from arkana.mcp import tools_workflow
        self.assertTrue(hasattr(tools_workflow, '_write_output_and_register_artifact'))

    def test_tools_pe_forensic_import(self):
        from arkana.mcp import tools_pe_forensic
        self.assertTrue(hasattr(tools_pe_forensic, '_write_output_and_register_artifact'))

    def test_tools_threat_intel_import(self):
        from arkana.mcp import tools_threat_intel
        self.assertTrue(hasattr(tools_threat_intel, '_write_output_and_register_artifact'))

    def test_tools_ioc_import(self):
        from arkana.mcp import tools_ioc
        self.assertTrue(hasattr(tools_ioc, '_write_output_and_register_artifact'))

    def test_tools_payload_import(self):
        from arkana.mcp import tools_payload
        self.assertTrue(hasattr(tools_payload, '_write_output_and_register_artifact'))

    def test_tools_crypto_import(self):
        from arkana.mcp import tools_crypto
        self.assertTrue(hasattr(tools_crypto, '_write_output_and_register_artifact'))


class TestExistingToolsStillHaveOutputPath(unittest.TestCase):
    """Verify the 3 tools that already had output_path still have it."""

    def test_refinery_xor_has_output_path(self):
        from arkana.mcp.tools_refinery import refinery_xor
        inner = getattr(refinery_xor, "__wrapped__", refinery_xor)
        sig = inspect.signature(inner)
        self.assertIn("output_path", sig.parameters)

    def test_refinery_carve_has_output_path(self):
        from arkana.mcp.tools_refinery import refinery_carve
        inner = getattr(refinery_carve, "__wrapped__", refinery_carve)
        sig = inspect.signature(inner)
        self.assertIn("output_path", sig.parameters)

    def test_refinery_pipeline_has_output_path(self):
        from arkana.mcp.tools_refinery import refinery_pipeline
        inner = getattr(refinery_pipeline, "__wrapped__", refinery_pipeline)
        sig = inspect.signature(inner)
        self.assertIn("output_path", sig.parameters)


if __name__ == "__main__":
    unittest.main()
