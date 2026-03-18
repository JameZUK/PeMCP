"""Tests for arkana.mcp.tools_vuln — vulnerability pattern detection."""
import pytest


# =====================================================================
#  Pattern Database Tests
# =====================================================================

class TestVulnPatternDatabase:
    """Tests for the vulnerability pattern definitions."""

    def test_patterns_not_empty(self):
        from arkana.mcp.tools_vuln import _VULN_PATTERNS
        assert len(_VULN_PATTERNS) >= 10

    def test_all_patterns_have_required_fields(self):
        from arkana.mcp.tools_vuln import _VULN_PATTERNS
        for pat in _VULN_PATTERNS:
            assert "id" in pat, f"Pattern missing 'id'"
            assert "name" in pat, f"Pattern {pat.get('id', '?')} missing 'name'"
            assert "severity" in pat, f"Pattern {pat['id']} missing 'severity'"
            assert "description" in pat, f"Pattern {pat['id']} missing 'description'"
            assert "pattern_type" in pat, f"Pattern {pat['id']} missing 'pattern_type'"

    def test_severities_valid(self):
        from arkana.mcp.tools_vuln import _VULN_PATTERNS
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for pat in _VULN_PATTERNS:
            assert pat["severity"] in valid_severities, (
                f"Pattern {pat['id']} has invalid severity: {pat['severity']}"
            )

    def test_pattern_types_valid(self):
        from arkana.mcp.tools_vuln import _VULN_PATTERNS
        valid_types = {"dangerous_api", "format_string", "unchecked_size", "decompile_pattern"}
        for pat in _VULN_PATTERNS:
            assert pat["pattern_type"] in valid_types, (
                f"Pattern {pat['id']} has invalid type: {pat['pattern_type']}"
            )

    def test_dangerous_api_patterns_have_apis(self):
        from arkana.mcp.tools_vuln import _VULN_PATTERNS
        for pat in _VULN_PATTERNS:
            if pat["pattern_type"] in ("dangerous_api", "format_string", "unchecked_size"):
                assert len(pat.get("dangerous_apis", [])) > 0, (
                    f"Pattern {pat['id']} (type={pat['pattern_type']}) has no dangerous_apis"
                )

    def test_decompile_patterns_have_regex(self):
        from arkana.mcp.tools_vuln import _VULN_PATTERNS
        for pat in _VULN_PATTERNS:
            if pat["pattern_type"] == "decompile_pattern":
                assert pat.get("regex"), (
                    f"Pattern {pat['id']} (decompile_pattern) missing regex"
                )

    def test_unique_ids(self):
        from arkana.mcp.tools_vuln import _VULN_PATTERNS
        ids = [p["id"] for p in _VULN_PATTERNS]
        assert len(ids) == len(set(ids)), "Duplicate pattern IDs found"


class TestDangerousApiLookup:
    """Tests for the API lookup dictionary."""

    def test_lookup_populated(self):
        from arkana.mcp.tools_vuln import _DANGEROUS_API_LOOKUP
        assert len(_DANGEROUS_API_LOOKUP) > 20

    def test_known_dangerous_apis(self):
        from arkana.mcp.tools_vuln import _DANGEROUS_API_LOOKUP
        assert "strcpy" in _DANGEROUS_API_LOOKUP
        assert "system" in _DANGEROUS_API_LOOKUP
        assert "memcpy" in _DANGEROUS_API_LOOKUP

    def test_lookup_entries_structure(self):
        from arkana.mcp.tools_vuln import _DANGEROUS_API_LOOKUP
        for _api_name, entries in _DANGEROUS_API_LOOKUP.items():
            assert isinstance(entries, list)
            for entry in entries:
                assert "id" in entry
                assert "name" in entry
                assert "severity" in entry


class TestCompiledPatterns:
    """Tests for precompiled regex patterns."""

    def test_patterns_compiled(self):
        from arkana.mcp.tools_vuln import _COMPILED_PATTERNS
        # At least some decompile_pattern entries should be compiled
        assert len(_COMPILED_PATTERNS) > 0

    def test_integer_overflow_pattern(self):
        from arkana.mcp.tools_vuln import _COMPILED_PATTERNS
        pat = _COMPILED_PATTERNS.get("INTEGER_OVERFLOW")
        if pat:
            assert pat.search("malloc(size + 16)") is not None
            assert pat.search("calloc(count * elem_size)") is not None

    def test_hardcoded_credentials_pattern(self):
        from arkana.mcp.tools_vuln import _COMPILED_PATTERNS
        pat = _COMPILED_PATTERNS.get("HARDCODED_CREDENTIALS")
        if pat:
            assert pat.search('password = "secret123"') is not None
            assert pat.search("api_key = 'abc12345'") is not None

    def test_double_free_pattern(self):
        from arkana.mcp.tools_vuln import _COMPILED_PATTERNS
        pat = _COMPILED_PATTERNS.get("DOUBLE_FREE")
        if pat:
            assert pat.search("free(ptr);\n  free(ptr);") is not None


class TestInputSourceApis:
    """Tests for the input source API set."""

    def test_input_apis_not_empty(self):
        from arkana.mcp.tools_vuln import _INPUT_SOURCE_APIS
        assert len(_INPUT_SOURCE_APIS) > 10

    def test_known_input_apis(self):
        from arkana.mcp.tools_vuln import _INPUT_SOURCE_APIS
        assert "recv" in _INPUT_SOURCE_APIS
        assert "fgets" in _INPUT_SOURCE_APIS
        assert "ReadFile" in _INPUT_SOURCE_APIS
        assert "getenv" in _INPUT_SOURCE_APIS


class TestDangerousSinkApis:
    """Tests for the dangerous sink API set."""

    def test_sink_apis_not_empty(self):
        from arkana.mcp.tools_vuln import _DANGEROUS_SINK_APIS
        assert len(_DANGEROUS_SINK_APIS) > 20

    def test_known_sink_apis(self):
        from arkana.mcp.tools_vuln import _DANGEROUS_SINK_APIS
        assert "strcpy" in _DANGEROUS_SINK_APIS
        assert "system" in _DANGEROUS_SINK_APIS


# =====================================================================
#  Sync Scan Tests (without angr)
# =====================================================================

class TestSyncScanAll:
    """Tests for the _sync_scan_all helper."""

    def test_scan_no_data(self):
        """Scan with no decompile cache and no angr should still work."""
        from arkana.mcp.tools_vuln import _sync_scan_all
        result = _sync_scan_all(target_addr=None, limit=50, severity_filter=None)
        assert "findings" in result
        assert "total_findings" in result
        assert "functions_scanned" in result
        assert "severity_summary" in result
        assert isinstance(result["findings"], list)

    def test_scan_single_function(self):
        from arkana.mcp.tools_vuln import _sync_scan_all
        result = _sync_scan_all(target_addr=0x401000, limit=50, severity_filter=None)
        assert result["functions_scanned"] == 1

    def test_severity_filter(self):
        from arkana.mcp.tools_vuln import _sync_scan_all
        result = _sync_scan_all(target_addr=None, limit=50, severity_filter="CRITICAL")
        for finding in result["findings"]:
            assert finding["severity"] == "CRITICAL"

    def test_limit_respected(self):
        from arkana.mcp.tools_vuln import _sync_scan_all
        result = _sync_scan_all(target_addr=None, limit=1, severity_filter=None)
        assert len(result["findings"]) <= 1

    def test_result_structure(self):
        from arkana.mcp.tools_vuln import _sync_scan_all
        result = _sync_scan_all(target_addr=None, limit=50, severity_filter=None)
        assert "patterns_matched" in result
        assert isinstance(result["patterns_matched"], dict)
        for key in ("CRITICAL", "HIGH", "MEDIUM"):
            assert key in result["severity_summary"]


class TestSyncAssessAttackSurface:
    """Tests for the _sync_assess_attack_surface helper."""

    def test_basic_assessment(self):
        from arkana.mcp.tools_vuln import _sync_assess_attack_surface
        result = _sync_assess_attack_surface(0x401000)
        assert "function_address" in result
        assert "risk_score" in result
        assert "risk_breakdown" in result
        assert "input_sources" in result
        assert "dangerous_sinks" in result
        assert "evidence" in result

    def test_risk_score_bounded(self):
        from arkana.mcp.tools_vuln import _sync_assess_attack_surface
        result = _sync_assess_attack_surface(0x401000)
        assert 0 <= result["risk_score"] <= 100

    def test_risk_level_assigned(self):
        from arkana.mcp.tools_vuln import _sync_assess_attack_surface
        result = _sync_assess_attack_surface(0x401000)
        assert result["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_address_formatting(self):
        from arkana.mcp.tools_vuln import _sync_assess_attack_surface
        result = _sync_assess_attack_surface(0x401000)
        assert result["function_address"] == "0x401000"


# =====================================================================
#  Tool Registration Tests
# =====================================================================

class TestToolRegistration:
    """Test that vuln tools are properly decorated."""

    def test_scan_tool(self):
        import asyncio
        from arkana.mcp.tools_vuln import scan_for_vulnerability_patterns
        assert asyncio.iscoroutinefunction(scan_for_vulnerability_patterns)

    def test_assess_tool(self):
        import asyncio
        from arkana.mcp.tools_vuln import assess_function_attack_surface
        assert asyncio.iscoroutinefunction(assess_function_attack_surface)
