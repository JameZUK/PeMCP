"""Tests for .NET deobfuscation tools — pure-Python helpers and command building."""
import inspect
import math
import os
import pytest

from arkana.mcp.tools_dotnet_deobfuscate import (
    _calc_shannon_entropy,
    _calc_name_entropy,
    _is_non_ascii,
    _match_custom_attributes,
    _match_resource_patterns,
    _classify_obfuscator,
    _build_de4dot_command,
    _build_nrs_command,
    _build_ilspycmd_command,
    _build_output_path,
    _parse_de4dot_output,
    _validate_type_name,
    _OBFUSCATOR_SIGNATURES,
)


# ── Shannon Entropy ───────────────────────────────────────────────────────

class TestCalcShannonEntropy:
    def test_empty_string(self):
        assert _calc_shannon_entropy("") == 0.0

    def test_single_char(self):
        assert _calc_shannon_entropy("aaaa") == 0.0

    def test_uniform_two_chars(self):
        # 50/50 split → entropy = 1.0
        result = _calc_shannon_entropy("aabb")
        assert abs(result - 1.0) < 0.01

    def test_normal_name(self):
        # Normal class names have moderate entropy
        e = _calc_shannon_entropy("MyClassName")
        assert 2.0 < e < 4.0

    def test_obfuscated_name(self):
        # Random-looking names have higher entropy
        e = _calc_shannon_entropy("x9Kp2mQ7vRtL")
        assert e > 3.0

    def test_all_unique_chars(self):
        # Every char different → max entropy
        s = "abcdefgh"
        e = _calc_shannon_entropy(s)
        assert abs(e - math.log2(8)) < 0.01


class TestCalcNameEntropy:
    def test_empty_list(self):
        assert _calc_name_entropy([]) == 0.0

    def test_single_name(self):
        result = _calc_name_entropy(["Hello"])
        assert result > 0

    def test_multiple_names(self):
        names = ["MyClass", "YourClass", "TheirClass"]
        result = _calc_name_entropy(names)
        assert result > 0

    def test_low_entropy_names(self):
        names = ["aaaa", "bbbb", "cccc"]
        result = _calc_name_entropy(names)
        assert result == 0.0  # All single-char repeats have 0 entropy


# ── Non-ASCII Detection ──────────────────────────────────────────────────

class TestIsNonAscii:
    def test_ascii_name(self):
        assert _is_non_ascii("MyClass") is False

    def test_unicode_name(self):
        assert _is_non_ascii("\u0410\u0411\u0412") is True

    def test_mixed_name(self):
        assert _is_non_ascii("My\u00fcClass") is True

    def test_empty_name(self):
        assert _is_non_ascii("") is False


# ── Custom Attribute Matching ────────────────────────────────────────────

class TestMatchCustomAttributes:
    def test_confuserex_match(self):
        attrs = ["ConfusedByAttribute", "SomeOther"]
        results = _match_custom_attributes(attrs, _OBFUSCATOR_SIGNATURES)
        assert len(results) >= 1
        assert any(r["obfuscator"] == "ConfuserEx" for r in results)
        assert all(r["confidence"] == "high" for r in results)

    def test_smartassembly_match(self):
        attrs = ["PoweredByAttribute"]
        results = _match_custom_attributes(attrs, _OBFUSCATOR_SIGNATURES)
        assert any(r["obfuscator"] == "SmartAssembly" for r in results)

    def test_no_match(self):
        attrs = ["System.Runtime.CompilerServices.CompilationRelaxationsAttribute"]
        results = _match_custom_attributes(attrs, _OBFUSCATOR_SIGNATURES)
        assert results == []

    def test_case_insensitive(self):
        attrs = ["CONFUSEDBYATTRIBUTE"]
        results = _match_custom_attributes(attrs, _OBFUSCATOR_SIGNATURES)
        assert len(results) >= 1

    def test_empty_attrs(self):
        results = _match_custom_attributes([], _OBFUSCATOR_SIGNATURES)
        assert results == []

    def test_dotfuscator_match(self):
        attrs = ["DotfuscatorAttribute"]
        results = _match_custom_attributes(attrs, _OBFUSCATOR_SIGNATURES)
        assert any(r["obfuscator"] == "Dotfuscator" for r in results)


# ── Resource Pattern Matching ────────────────────────────────────────────

class TestMatchResourcePatterns:
    def test_reactor_match(self):
        resources = ["__$some_resource"]
        results = _match_resource_patterns(resources, _OBFUSCATOR_SIGNATURES)
        assert any(r["obfuscator"] == ".NET Reactor" for r in results)
        assert all(r["confidence"] == "medium" for r in results)

    def test_confuserex_resource(self):
        resources = ["ConfuserEx.Runtime"]
        results = _match_resource_patterns(resources, _OBFUSCATOR_SIGNATURES)
        assert any(r["obfuscator"] == "ConfuserEx" for r in results)

    def test_no_match(self):
        resources = ["MyApp.Properties.Resources"]
        results = _match_resource_patterns(resources, _OBFUSCATOR_SIGNATURES)
        assert results == []

    def test_empty_resources(self):
        results = _match_resource_patterns([], _OBFUSCATOR_SIGNATURES)
        assert results == []


# ── Classify Obfuscator ─────────────────────────────────────────────────

class TestClassifyObfuscator:
    def test_with_detections(self):
        detections = [
            {"obfuscator": "ConfuserEx", "confidence": "high",
             "evidence": "test", "recommended_tool": "de4dot", "sig_id": "confuserex"},
        ]
        indicators = {"non_ascii_name_pct": 0, "type_name_entropy": 2.0}
        is_obf, unique = _classify_obfuscator(detections, indicators)
        assert is_obf is True
        assert len(unique) == 1
        assert "sig_id" not in unique[0]  # Internal field removed

    def test_no_detections_clean(self):
        indicators = {"non_ascii_name_pct": 5, "type_name_entropy": 2.5}
        is_obf, unique = _classify_obfuscator([], indicators)
        assert is_obf is False
        assert unique == []

    def test_generic_high_entropy(self):
        indicators = {"non_ascii_name_pct": 10, "type_name_entropy": 5.0}
        is_obf, unique = _classify_obfuscator([], indicators)
        assert is_obf is True
        assert unique[0]["confidence"] == "low"
        assert "Unknown" in unique[0]["obfuscator"]

    def test_generic_high_non_ascii(self):
        indicators = {"non_ascii_name_pct": 60, "type_name_entropy": 2.0}
        is_obf, unique = _classify_obfuscator([], indicators)
        assert is_obf is True

    def test_dedup_keeps_highest_confidence(self):
        detections = [
            {"obfuscator": "ConfuserEx", "confidence": "medium",
             "evidence": "resource", "recommended_tool": "de4dot", "sig_id": "confuserex"},
            {"obfuscator": "ConfuserEx", "confidence": "high",
             "evidence": "attr", "recommended_tool": "de4dot", "sig_id": "confuserex"},
        ]
        indicators = {"non_ascii_name_pct": 0, "type_name_entropy": 2.0}
        is_obf, unique = _classify_obfuscator(detections, indicators)
        assert len(unique) == 1
        assert unique[0]["confidence"] == "high"


# ── Command Building ─────────────────────────────────────────────────────

class TestBuildDe4dotCommand:
    def test_normal_mode(self):
        args = _build_de4dot_command("/path/in.exe", "/path/out.exe")
        assert args[0] == "mono"
        assert "-f" in args
        assert "/path/in.exe" in args
        assert "-o" in args
        assert "/path/out.exe" in args

    def test_detect_only(self):
        args = _build_de4dot_command("/path/in.exe", detect_only=True)
        assert "--detect-only" in args
        assert "-f" in args
        assert "-o" not in args
        # --detect-only must come before -f
        assert args.index("--detect-only") < args.index("-f")

    def test_no_output(self):
        args = _build_de4dot_command("/path/in.exe")
        assert "-f" in args
        assert "-o" not in args


class TestBuildNrsCommand:
    def test_basic(self):
        args = _build_nrs_command("/path/in.exe", "/tmp/output")
        assert "NETReactorSlayer" in args[0]
        assert "/path/in.exe" in args
        assert "-o" in args
        assert "/tmp/output" in args


class TestBuildIlspycmdCommand:
    def test_basic(self):
        args = _build_ilspycmd_command("/path/in.dll")
        assert "/path/in.dll" in args
        assert "-t" not in args
        assert "-o" not in args

    def test_with_type(self):
        args = _build_ilspycmd_command("/path/in.dll", type_name="MyNS.MyClass")
        assert "-t" in args
        assert "MyNS.MyClass" in args

    def test_with_output_dir(self):
        args = _build_ilspycmd_command("/path/in.dll", output_dir="/tmp/out")
        assert "-o" in args
        assert "/tmp/out" in args
        assert "-p" in args

    def test_with_all_options(self):
        args = _build_ilspycmd_command(
            "/path/in.dll", type_name="Foo.Bar", output_dir="/tmp/out"
        )
        assert "-t" in args
        assert "Foo.Bar" in args
        assert "-o" in args
        assert "-p" in args


# ── Output Path Building ────────────────────────────────────────────────

class TestBuildOutputPath:
    def test_basic(self):
        path = _build_output_path("/samples/malware.exe")
        assert "malware_deobfuscated.exe" in path

    def test_custom_suffix(self):
        path = _build_output_path("/samples/test.dll", suffix="_cleaned")
        assert "test_cleaned.dll" in path

    def test_no_extension(self):
        path = _build_output_path("/samples/payload")
        assert "payload_deobfuscated.exe" in path


# ── de4dot Output Parsing ───────────────────────────────────────────────

class TestParseDe4dotOutput:
    def test_detected_line(self):
        stdout = "Detected ConfuserEx v0.6.0\nCleaned file saved to output.exe"
        result = _parse_de4dot_output(stdout)
        assert "ConfuserEx" in result.get("detected_obfuscator", "")
        assert result.get("status") == "success"

    def test_no_detection(self):
        stdout = "Processing...\nDone."
        result = _parse_de4dot_output(stdout)
        assert "detected_obfuscator" not in result

    def test_empty_output(self):
        result = _parse_de4dot_output("")
        assert "raw_output" in result

    def test_output_truncated(self):
        stdout = "x" * 1000
        result = _parse_de4dot_output(stdout)
        assert len(result["raw_output"]) == 500


# ── Type Name Validation ────────────────────────────────────────────────

class TestValidateTypeName:
    def test_valid_simple(self):
        assert _validate_type_name("MyClass") == "MyClass"

    def test_valid_namespace(self):
        assert _validate_type_name("System.Collections.Generic.List") == "System.Collections.Generic.List"

    def test_valid_generic(self):
        assert _validate_type_name("List`1[System.String]") == "List`1[System.String]"

    def test_valid_nested(self):
        assert _validate_type_name("Outer+Inner") == "Outer+Inner"

    def test_reject_semicolon(self):
        with pytest.raises(ValueError, match="disallowed"):
            _validate_type_name("Foo;Bar")

    def test_reject_pipe(self):
        with pytest.raises(ValueError, match="disallowed"):
            _validate_type_name("Foo|Bar")

    def test_reject_too_long(self):
        with pytest.raises(ValueError, match="too long"):
            _validate_type_name("A" * 501)

    def test_reject_shell_chars(self):
        for ch in ["|", ";", "&", "$", "(", ")", "{", "}"]:
            with pytest.raises(ValueError):
                _validate_type_name(f"Foo{ch}Bar")


# ── Method Selection (auto logic) ───────────────────────────────────────

class TestMethodSelection:
    """Test the method selection logic conceptually — we can't run the full
    async tools without a server, but we can verify detection→tool mapping."""

    def test_reactor_detection_recommends_nrs(self):
        """When .NET Reactor is detected, recommended_tool should be reactor_slayer."""
        sigs = _OBFUSCATOR_SIGNATURES["dotnet_reactor"]
        assert sigs["recommended_tool"] == "reactor_slayer"

    def test_confuserex_recommends_de4dot(self):
        sigs = _OBFUSCATOR_SIGNATURES["confuserex"]
        assert sigs["recommended_tool"] == "de4dot"

    def test_all_sigs_have_recommended_tool(self):
        for sig_id, sig in _OBFUSCATOR_SIGNATURES.items():
            assert "recommended_tool" in sig, f"Missing recommended_tool for {sig_id}"
            assert sig["recommended_tool"] in ("de4dot", "reactor_slayer")


# ── Tool Registration ───────────────────────────────────────────────────

class TestToolRegistration:
    def test_detect_importable(self):
        from arkana.mcp.tools_dotnet_deobfuscate import detect_dotnet_obfuscation
        assert inspect.iscoroutinefunction(detect_dotnet_obfuscation)

    def test_deobfuscate_importable(self):
        from arkana.mcp.tools_dotnet_deobfuscate import dotnet_deobfuscate
        assert inspect.iscoroutinefunction(dotnet_deobfuscate)

    def test_decompile_importable(self):
        from arkana.mcp.tools_dotnet_deobfuscate import dotnet_decompile
        assert inspect.iscoroutinefunction(dotnet_decompile)
