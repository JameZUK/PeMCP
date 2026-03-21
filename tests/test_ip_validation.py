"""Tests for IP octet validation in triage and category maps.

Ensures that IP regexes reject octets > 255 (e.g. reversed strings like
"401.14.631.8") and that is_benign_ip() treats invalid IPs as benign (filtered).
"""

import re

import pytest


class TestTriageIPRegex:
    """Test _TRIAGE_IP_RE rejects invalid octets."""

    def setup_method(self):
        from arkana.mcp.tools_triage import _TRIAGE_IP_RE
        self.regex = _TRIAGE_IP_RE

    def test_valid_ip_matches(self):
        assert self.regex.search("192.168.1.1")
        assert self.regex.search("10.0.0.1")
        assert self.regex.search("255.255.255.255")
        assert self.regex.search("0.0.0.0")
        assert self.regex.search("8.8.8.8")

    def test_octet_boundary_values(self):
        assert self.regex.search("255.255.255.255")
        assert self.regex.search("0.0.0.0")
        assert self.regex.search("249.249.249.249")
        assert self.regex.search("1.2.3.4")

    def test_rejects_octets_above_255(self):
        # Reversed string "401.14.631.8" — the ValleyRAT false positive
        match = self.regex.search("401.14.631.8")
        assert match is None, f"Should not match reversed IP, got: {match.group()}"

    def test_256_does_not_match_full_string(self):
        """256.0.0.1 may match substring '56.0.0.1' but not the full invalid IP."""
        m = self.regex.search("256.0.0.1")
        if m:
            # It matched a valid substring, which is fine
            assert m.group() == "56.0.0.1"

    def test_rejects_all_large_octets(self):
        """When all octets are >255, no valid IP substring exists."""
        assert self.regex.search("999.999.999.999") is None
        assert self.regex.search("400.500.600.700") is None

    def test_extracts_valid_ip_from_surrounding_text(self):
        text = "The C2 server is at 8.136.14.104 on port 3323"
        m = self.regex.search(text)
        assert m is not None
        assert m.group() == "8.136.14.104"


class TestCategoryMapsIPRegex:
    """Test STRING_CATEGORY_PATTERNS['ip_addresses'] rejects invalid octets."""

    def setup_method(self):
        from arkana.mcp._category_maps import STRING_CATEGORY_PATTERNS
        self.regex = STRING_CATEGORY_PATTERNS["ip_addresses"]

    def test_valid_ip_matches(self):
        assert self.regex.search("192.168.1.1")
        assert self.regex.search("10.0.0.1")

    def test_rejects_octets_above_255(self):
        assert self.regex.search("401.14.631.8") is None
        assert self.regex.search("999.999.999.999") is None


class TestIsBenignIP:
    """Test is_benign_ip() behavior for valid and invalid IPs."""

    def setup_method(self):
        from arkana.mcp._category_maps import is_benign_ip
        self.is_benign_ip = is_benign_ip

    def test_private_ips_are_benign(self):
        assert self.is_benign_ip("192.168.1.1") is True
        assert self.is_benign_ip("10.0.0.1") is True
        assert self.is_benign_ip("172.16.0.1") is True

    def test_loopback_is_benign(self):
        assert self.is_benign_ip("127.0.0.1") is True

    def test_public_ip_not_benign(self):
        assert self.is_benign_ip("8.8.8.8") is False
        assert self.is_benign_ip("8.136.14.104") is False

    def test_invalid_ip_treated_as_benign(self):
        """Invalid IPs should return True (be filtered out), not False."""
        assert self.is_benign_ip("401.14.631.8") is True
        assert self.is_benign_ip("999.999.999.999") is True
        assert self.is_benign_ip("not_an_ip") is True

    def test_multicast_is_benign(self):
        assert self.is_benign_ip("224.0.0.1") is True

    def test_reserved_is_benign(self):
        assert self.is_benign_ip("240.0.0.1") is True


class TestConsistencyWithToolsIOC:
    """Verify triage IP handling matches the canonical tools_ioc.py behavior."""

    def test_both_regexes_reject_same_invalid_ips(self):
        from arkana.mcp.tools_triage import _TRIAGE_IP_RE
        from arkana.mcp.tools_ioc import _IP_RE

        # These strings contain no valid IP as a substring
        invalid_ips = ["401.14.631.8", "999.999.999.999", "400.500.600.700"]
        for ip in invalid_ips:
            assert _TRIAGE_IP_RE.search(ip) is None, f"_TRIAGE_IP_RE matched invalid: {ip}"
            assert _IP_RE.search(ip) is None, f"_IP_RE matched invalid: {ip}"

    def test_both_regexes_match_same_valid_ips(self):
        from arkana.mcp.tools_triage import _TRIAGE_IP_RE
        from arkana.mcp.tools_ioc import _IP_RE

        valid_ips = ["192.168.1.1", "8.8.8.8", "255.255.255.255", "0.0.0.0"]
        for ip in valid_ips:
            assert _TRIAGE_IP_RE.search(ip) is not None, f"_TRIAGE_IP_RE missed: {ip}"
            assert _IP_RE.search(ip) is not None, f"_IP_RE missed: {ip}"

    def test_benign_ip_consistent_with_non_routable(self):
        """is_benign_ip and _is_non_routable_ip should agree on invalid IPs."""
        from arkana.mcp._category_maps import is_benign_ip
        from arkana.mcp.tools_ioc import _is_non_routable_ip

        # Both should return True for invalid IPs
        assert is_benign_ip("401.14.631.8") is True
        assert _is_non_routable_ip("401.14.631.8") is True
