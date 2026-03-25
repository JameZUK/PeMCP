"""Unit tests for sandbox report parsers in arkana/parsers/sandbox.py."""
import pytest

from arkana.parsers.sandbox import (
    detect_sandbox_format,
    parse_sandbox_report,
    _validate_and_normalize,
    _empty_report,
    _parse_cape,
    _parse_cuckoo,
    _parse_anyrun,
    _parse_hybrid_analysis,
    _parse_joe,
)


# ---------------------------------------------------------------------------
# detect_sandbox_format
# ---------------------------------------------------------------------------

class TestDetectSandboxFormat:
    """Tests for auto-detection of sandbox report format."""

    def test_detect_cape(self):
        data = {"CAPE": {"configs": []}, "target": {}}
        assert detect_sandbox_format(data) == "cape"

    def test_detect_cuckoo(self):
        data = {"behavior": {"processes": []}, "target": {}}
        assert detect_sandbox_format(data) == "cuckoo"

    def test_cape_takes_priority_over_cuckoo(self):
        """CAPE also has behavior/processes but CAPE key takes precedence."""
        data = {"CAPE": {}, "behavior": {"processes": []}}
        assert detect_sandbox_format(data) == "cape"

    def test_detect_anyrun(self):
        data = {"processes": [{"uuid": "abc-123", "pid": 1}]}
        assert detect_sandbox_format(data) == "anyrun"

    def test_detect_anyrun_requires_uuid(self):
        """Processes without uuid should not trigger ANY.RUN detection."""
        data = {"processes": [{"pid": 1, "name": "test"}]}
        assert detect_sandbox_format(data) != "anyrun"

    def test_detect_hybrid_analysis_mitre(self):
        data = {"mitre_attcks": [{"technique": "T1055"}]}
        assert detect_sandbox_format(data) == "hybrid_analysis"

    def test_detect_hybrid_analysis_verdict_and_score(self):
        data = {"verdict": 5, "threat_score": 80}
        assert detect_sandbox_format(data) == "hybrid_analysis"

    def test_detect_joe_mitreattack(self):
        data = {"mitreattack": {"tactic": []}}
        assert detect_sandbox_format(data) == "joe"

    def test_detect_joe_signaturedetections(self):
        data = {"signaturedetections": {"strategy": []}}
        assert detect_sandbox_format(data) == "joe"

    def test_detect_unknown(self):
        data = {"random_key": "value"}
        assert detect_sandbox_format(data) == "unknown"

    def test_detect_empty_dict(self):
        assert detect_sandbox_format({}) == "unknown"


# ---------------------------------------------------------------------------
# parse_sandbox_report — unknown format
# ---------------------------------------------------------------------------

class TestParseSandboxReportUnknown:

    def test_unknown_format_returns_error(self):
        result = parse_sandbox_report({"random": "data"}, format="nosuchformat")
        assert "error" in result
        assert "Unknown sandbox format" in result["error"]

    def test_auto_detect_unknown_returns_error(self):
        result = parse_sandbox_report({"random": "data"}, format="auto")
        assert "error" in result


# ---------------------------------------------------------------------------
# CAPE Parser
# ---------------------------------------------------------------------------

class TestParseCape:
    """Tests for CAPE Sandbox report parsing."""

    def _minimal_cape(self):
        return {
            "CAPE": {
                "configs": [
                    {"type": "Emotet", "c2": ["1.2.3.4:443", "5.6.7.8:8080"]}
                ]
            },
            "target": {
                "file": {
                    "sha256": "abc123",
                    "md5": "def456",
                    "sha1": "ghi789",
                    "name": "malware.exe",
                    "size": 12345,
                }
            },
            "network": {
                "dns": [
                    {
                        "request": "evil.com",
                        "answers": [{"type": "A", "data": "1.2.3.4"}],
                    }
                ],
                "http": [],
                "tcp": [{"dst": "1.2.3.4", "dport": 443}],
                "udp": [],
            },
            "behavior": {"processes": []},
            "malscore": 8,
            "signatures": [],
        }

    def test_cape_sample_hashes(self):
        data = self._minimal_cape()
        result = parse_sandbox_report(data, format="cape")
        assert result["sample"]["sha256"] == "abc123"
        assert result["sample"]["md5"] == "def456"
        assert result["sample"]["filename"] == "malware.exe"

    def test_cape_verdict_malicious(self):
        data = self._minimal_cape()
        data["malscore"] = 8
        result = parse_sandbox_report(data, format="cape")
        assert result["verdict"] == "malicious"

    def test_cape_verdict_suspicious(self):
        data = self._minimal_cape()
        data["malscore"] = 3
        result = parse_sandbox_report(data, format="cape")
        assert result["verdict"] == "suspicious"

    def test_cape_network_dns(self):
        data = self._minimal_cape()
        result = parse_sandbox_report(data, format="cape")
        assert len(result["network"]["dns_queries"]) >= 1
        assert result["network"]["dns_queries"][0]["domain"] == "evil.com"

    def test_cape_extracted_config(self):
        data = self._minimal_cape()
        result = parse_sandbox_report(data, format="cape")
        assert result["extracted_config"] is not None
        assert result["extracted_config"]["family"] == "Emotet"
        assert "1.2.3.4:443" in result["extracted_config"]["c2_servers"]

    def test_cape_malware_family(self):
        data = self._minimal_cape()
        result = parse_sandbox_report(data, format="cape")
        assert result["malware_family"] == "Emotet"

    def test_cape_sandbox_field_set(self):
        data = self._minimal_cape()
        result = parse_sandbox_report(data, format="cape")
        assert result["sandbox"] == "cape"

    def test_cape_threat_score_clamped(self):
        data = self._minimal_cape()
        data["malscore"] = 15
        result = parse_sandbox_report(data, format="cape")
        assert result["threat_score"] <= 100


# ---------------------------------------------------------------------------
# Cuckoo Parser
# ---------------------------------------------------------------------------

class TestParseCuckoo:
    """Tests for Cuckoo Sandbox report parsing."""

    def _minimal_cuckoo(self):
        return {
            "target": {
                "file": {
                    "sha256": "cuckoo_sha",
                    "md5": "cuckoo_md5",
                    "sha1": "cuckoo_sha1",
                    "name": "sample.exe",
                    "size": 5000,
                }
            },
            "info": {"score": 7},
            "network": {
                "dns": [],
                "http": [{"uri": "http://evil.com/gate.php", "method": "POST", "host": "evil.com", "port": 80}],
                "tcp": [],
                "udp": [],
            },
            "behavior": {
                "processes": [
                    {"pid": 1234, "ppid": 1000, "process_name": "sample.exe", "command_line": "sample.exe"},
                    {"pid": 1235, "ppid": 1234, "process_name": "cmd.exe", "command_line": "cmd /c whoami"},
                ],
                "apistats": {
                    "1234": {"NtCreateFile": 5, "NtWriteFile": 3},
                },
                "enhanced": [
                    {"event": "file_created", "path": "C:\\temp\\payload.bin"},
                ],
                "summary": {
                    "mutex": ["Global\\MyMutex"],
                    "regkey_written": ["HKLM\\SOFTWARE\\Test"],
                },
            },
            "signatures": [
                {
                    "name": "creates_exe",
                    "description": "Creates executable files",
                    "severity": 3,
                    "marks": [{"attack_id": "T1204"}],
                    "ttp": ["T1059"],
                }
            ],
            "dropped": [
                {"name": "dropped.dll", "sha256": "drop_sha", "md5": "drop_md5", "size": 1000, "type": "PE32"},
            ],
        }

    def test_cuckoo_processes(self):
        data = self._minimal_cuckoo()
        result = parse_sandbox_report(data, format="cuckoo")
        assert len(result["processes"]) == 2
        assert result["processes"][0]["name"] == "sample.exe"
        assert result["processes"][0]["is_main"] is True
        assert result["processes"][1]["name"] == "cmd.exe"

    def test_cuckoo_network_http(self):
        data = self._minimal_cuckoo()
        result = parse_sandbox_report(data, format="cuckoo")
        assert len(result["network"]["http_requests"]) >= 1
        assert result["network"]["http_requests"][0]["url"] == "http://evil.com/gate.php"

    def test_cuckoo_signatures(self):
        data = self._minimal_cuckoo()
        result = parse_sandbox_report(data, format="cuckoo")
        assert len(result["signatures"]) >= 1
        assert result["signatures"][0]["name"] == "creates_exe"
        assert result["signatures"][0]["severity"] == "high"

    def test_cuckoo_mitre_from_signatures(self):
        data = self._minimal_cuckoo()
        result = parse_sandbox_report(data, format="cuckoo")
        technique_ids = [t["id"] for t in result["mitre_techniques"]]
        assert "T1204" in technique_ids or "T1059" in technique_ids

    def test_cuckoo_dropped_files(self):
        data = self._minimal_cuckoo()
        result = parse_sandbox_report(data, format="cuckoo")
        assert len(result["files"]["dropped"]) >= 1
        assert result["files"]["dropped"][0]["filename"] == "dropped.dll"

    def test_cuckoo_api_summary(self):
        data = self._minimal_cuckoo()
        result = parse_sandbox_report(data, format="cuckoo")
        assert result["api_summary"]["total_calls"] == 8  # 5 + 3
        assert len(result["api_summary"]["top_apis"]) >= 1

    def test_cuckoo_mutexes(self):
        data = self._minimal_cuckoo()
        result = parse_sandbox_report(data, format="cuckoo")
        assert "Global\\MyMutex" in result["files"]["mutexes"]

    def test_cuckoo_registry_keys(self):
        data = self._minimal_cuckoo()
        result = parse_sandbox_report(data, format="cuckoo")
        assert "HKLM\\SOFTWARE\\Test" in result["files"]["registry_keys"]

    def test_cuckoo_verdict(self):
        data = self._minimal_cuckoo()
        result = parse_sandbox_report(data, format="cuckoo")
        assert result["verdict"] == "malicious"


# ---------------------------------------------------------------------------
# ANY.RUN Parser
# ---------------------------------------------------------------------------

class TestParseAnyrun:
    """Tests for ANY.RUN report parsing."""

    def _minimal_anyrun(self):
        return {
            "analysis": {
                "content": {
                    "hashes": {"sha256": "anyrun_sha", "md5": "anyrun_md5", "sha1": "anyrun_sha1"},
                    "fileName": "test.exe",
                    "fileSize": 8000,
                }
            },
            "processes": [
                {
                    "uuid": "proc-1",
                    "pid": 100,
                    "ppid": 4,
                    "image": "test.exe",
                    "commandLine": "test.exe --run",
                    "mainProcess": True,
                },
                {
                    "uuid": "proc-2",
                    "pid": 200,
                    "ppid": 100,
                    "image": "cmd.exe",
                    "commandLine": "cmd /c echo hello",
                    "mainProcess": False,
                },
            ],
            "network": {
                "dnsRequests": [
                    {"domain": "c2server.com", "ips": ["10.0.0.1"]},
                ],
                "httpRequests": [
                    {"url": "http://c2server.com/beacon", "method": "GET", "host": "c2server.com", "port": 80},
                ],
                "connections": [
                    {"ip": "10.0.0.1", "port": 443, "protocol": "tcp"},
                ],
            },
            "mitre": [
                {"id": "T1071", "name": "Application Layer Protocol", "phases": ["command-and-control"]},
            ],
            "incidents": [
                {"title": "Suspicious network activity", "desc": "Connects to known C2", "threatLevel": 2,
                 "mitre": ["T1071"]},
            ],
        }

    def test_anyrun_processes_with_uuid(self):
        data = self._minimal_anyrun()
        result = parse_sandbox_report(data, format="anyrun")
        assert len(result["processes"]) == 2
        assert result["processes"][0]["is_main"] is True
        assert result["processes"][0]["name"] == "test.exe"

    def test_anyrun_network_connections(self):
        data = self._minimal_anyrun()
        result = parse_sandbox_report(data, format="anyrun")
        assert len(result["network"]["connections"]) >= 1
        assert result["network"]["connections"][0]["ip"] == "10.0.0.1"

    def test_anyrun_mitre_techniques(self):
        data = self._minimal_anyrun()
        result = parse_sandbox_report(data, format="anyrun")
        assert len(result["mitre_techniques"]) >= 1
        assert result["mitre_techniques"][0]["id"] == "T1071"
        assert result["mitre_techniques"][0]["tactic"] == "command-and-control"

    def test_anyrun_signatures_from_incidents(self):
        data = self._minimal_anyrun()
        result = parse_sandbox_report(data, format="anyrun")
        assert len(result["signatures"]) >= 1
        assert result["signatures"][0]["name"] == "Suspicious network activity"
        assert result["signatures"][0]["severity"] == "high"

    def test_anyrun_dns_queries(self):
        data = self._minimal_anyrun()
        result = parse_sandbox_report(data, format="anyrun")
        assert len(result["network"]["dns_queries"]) >= 1
        assert result["network"]["dns_queries"][0]["domain"] == "c2server.com"

    def test_anyrun_sample_info(self):
        data = self._minimal_anyrun()
        result = parse_sandbox_report(data, format="anyrun")
        assert result["sample"]["sha256"] == "anyrun_sha"
        assert result["sample"]["filename"] == "test.exe"

    def test_anyrun_contacted_domains(self):
        data = self._minimal_anyrun()
        result = parse_sandbox_report(data, format="anyrun")
        assert "c2server.com" in result["network"]["contacted_domains"]


# ---------------------------------------------------------------------------
# Hybrid Analysis Parser
# ---------------------------------------------------------------------------

class TestParseHybridAnalysis:
    """Tests for Hybrid Analysis (Falcon Sandbox) report parsing."""

    def _minimal_ha(self):
        return {
            "sha256": "ha_sha256",
            "md5": "ha_md5",
            "sha1": "ha_sha1",
            "submit_name": "suspicious.exe",
            "size": 15000,
            "verdict": 5,
            "threat_score": 85,
            "vx_family": "TrickBot",
            "domains": ["evil-domain.com"],
            "hosts": ["192.168.1.100"],
            "mitre_attcks": [
                {"technique": "T1055", "tactic": "defense-evasion"},
            ],
            "signatures": [
                {"name": "injection", "description": "Process injection detected",
                 "threat_level_human": "alert", "attck_id": "T1055"},
            ],
            "extracted_files": [
                {"name": "config.bin", "sha256": "cfg_sha", "md5": "cfg_md5",
                 "file_size": 500, "type_tags": ["binary"]},
            ],
        }

    def test_ha_verdict_mapping(self):
        data = self._minimal_ha()
        # verdict 5 = malicious
        result = parse_sandbox_report(data, format="hybrid_analysis")
        assert result["verdict"] == "malicious"

    def test_ha_verdict_clean(self):
        data = self._minimal_ha()
        data["verdict"] = 1
        result = parse_sandbox_report(data, format="hybrid_analysis")
        assert result["verdict"] == "clean"

    def test_ha_verdict_suspicious(self):
        data = self._minimal_ha()
        data["verdict"] = 3
        result = parse_sandbox_report(data, format="hybrid_analysis")
        assert result["verdict"] == "suspicious"

    def test_ha_threat_score(self):
        data = self._minimal_ha()
        result = parse_sandbox_report(data, format="hybrid_analysis")
        assert result["threat_score"] == 85

    def test_ha_malware_family(self):
        data = self._minimal_ha()
        result = parse_sandbox_report(data, format="hybrid_analysis")
        assert result["malware_family"] == "TrickBot"

    def test_ha_domains_and_hosts(self):
        data = self._minimal_ha()
        result = parse_sandbox_report(data, format="hybrid_analysis")
        assert "evil-domain.com" in result["network"]["contacted_domains"]
        # hosts go through IP validation in _validate_and_normalize
        assert len(result["network"]["connections"]) >= 1

    def test_ha_mitre(self):
        data = self._minimal_ha()
        result = parse_sandbox_report(data, format="hybrid_analysis")
        assert len(result["mitre_techniques"]) >= 1
        assert result["mitre_techniques"][0]["id"] == "T1055"

    def test_ha_signatures(self):
        data = self._minimal_ha()
        result = parse_sandbox_report(data, format="hybrid_analysis")
        assert len(result["signatures"]) >= 1
        assert result["signatures"][0]["severity"] == "critical"

    def test_ha_dropped_files(self):
        data = self._minimal_ha()
        result = parse_sandbox_report(data, format="hybrid_analysis")
        assert len(result["files"]["dropped"]) >= 1
        assert result["files"]["dropped"][0]["filename"] == "config.bin"


# ---------------------------------------------------------------------------
# Joe Sandbox Parser
# ---------------------------------------------------------------------------

class TestParseJoe:
    """Tests for Joe Sandbox report parsing."""

    def _minimal_joe(self):
        return {
            "fileinfo": {
                "sha256": "joe_sha256",
                "md5": "joe_md5",
                "sha1": "joe_sha1",
                "filename": "payload.exe",
                "filesize": 20000,
            },
            "ipinfo": {
                "ip": [
                    {"@ip": "93.184.216.34"},
                    {"@ip": "10.0.0.1"},
                ]
            },
            "domaininfo": {
                "domain": [
                    {"@name": "malware-c2.net"},
                ]
            },
            "mitreattack": {
                "tactic": [
                    {
                        "name": "Execution",
                        "technique": [
                            {"id": "T1059", "name": "Command and Scripting Interpreter"},
                        ],
                    }
                ]
            },
            "signatureinfo": {
                "sig": [
                    {"@desc": "Suspicious behavior detected", "@name": "susp_behavior", "@impact": "2"},
                ]
            },
        }

    def test_joe_sample_info(self):
        data = self._minimal_joe()
        result = parse_sandbox_report(data, format="joe")
        assert result["sample"]["sha256"] == "joe_sha256"
        assert result["sample"]["filename"] == "payload.exe"
        assert result["sample"]["file_size"] == 20000

    def test_joe_ip_with_at_key(self):
        """Joe uses @ip keys from XML-to-JSON conversion."""
        data = self._minimal_joe()
        result = parse_sandbox_report(data, format="joe")
        connections = result["network"]["connections"]
        ips = [c["ip"] for c in connections]
        assert "93.184.216.34" in ips

    def test_joe_domain_with_at_name_key(self):
        """Joe uses @name keys from XML-to-JSON conversion."""
        data = self._minimal_joe()
        result = parse_sandbox_report(data, format="joe")
        assert "malware-c2.net" in result["network"]["contacted_domains"]

    def test_joe_mitre_techniques(self):
        data = self._minimal_joe()
        result = parse_sandbox_report(data, format="joe")
        assert len(result["mitre_techniques"]) >= 1
        assert result["mitre_techniques"][0]["id"] == "T1059"
        assert result["mitre_techniques"][0]["tactic"] == "Execution"

    def test_joe_signatures(self):
        data = self._minimal_joe()
        result = parse_sandbox_report(data, format="joe")
        assert len(result["signatures"]) >= 1
        assert result["signatures"][0]["name"] == "Suspicious behavior detected"
        assert result["signatures"][0]["severity"] == "high"

    def test_joe_single_ip_as_dict(self):
        """Joe sometimes returns a single ip as a dict instead of list."""
        data = self._minimal_joe()
        data["ipinfo"]["ip"] = {"@ip": "1.2.3.4"}
        result = parse_sandbox_report(data, format="joe")
        ips = [c["ip"] for c in result["network"]["connections"]]
        assert "1.2.3.4" in ips

    def test_joe_single_domain_as_dict(self):
        """Joe sometimes returns a single domain as dict instead of list."""
        data = self._minimal_joe()
        data["domaininfo"]["domain"] = {"@name": "single.domain.com"}
        result = parse_sandbox_report(data, format="joe")
        assert "single.domain.com" in result["network"]["contacted_domains"]

    def test_joe_single_tactic_as_dict(self):
        """Joe sometimes wraps a single tactic as a dict."""
        data = self._minimal_joe()
        data["mitreattack"]["tactic"] = {
            "name": "Persistence",
            "technique": {"id": "T1547", "name": "Boot or Logon Autostart Execution"},
        }
        result = parse_sandbox_report(data, format="joe")
        assert any(t["id"] == "T1547" for t in result["mitre_techniques"])

    def test_joe_single_sig_as_dict(self):
        """Joe sometimes wraps a single signature as a dict."""
        data = self._minimal_joe()
        data["signatureinfo"]["sig"] = {"@desc": "Single finding", "@impact": "3"}
        result = parse_sandbox_report(data, format="joe")
        assert len(result["signatures"]) >= 1
        assert result["signatures"][0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# _validate_and_normalize
# ---------------------------------------------------------------------------

class TestValidateAndNormalize:
    """Tests for the post-parse validation and normalization step."""

    def test_verdict_normalized_to_unknown(self):
        report = _empty_report()
        report["verdict"] = "maybe_bad"
        _validate_and_normalize(report)
        assert report["verdict"] == "unknown"

    def test_valid_verdicts_preserved(self):
        for v in ("clean", "suspicious", "malicious"):
            report = _empty_report()
            report["verdict"] = v
            _validate_and_normalize(report)
            assert report["verdict"] == v

    def test_threat_score_clamped_high(self):
        report = _empty_report()
        report["threat_score"] = 999
        _validate_and_normalize(report)
        assert report["threat_score"] == 100

    def test_threat_score_clamped_low(self):
        report = _empty_report()
        report["threat_score"] = -50
        _validate_and_normalize(report)
        assert report["threat_score"] == 0

    def test_threat_score_none_preserved(self):
        report = _empty_report()
        report["threat_score"] = None
        _validate_and_normalize(report)
        assert report["threat_score"] is None

    def test_invalid_ips_filtered(self):
        report = _empty_report()
        report["network"]["contacted_ips"] = [
            "192.168.1.1",
            "not_an_ip",
            "",
            "10.0.0.1",
            "999.999.999.999",  # Invalid octets but matches regex pattern
        ]
        _validate_and_normalize(report)
        valid = report["network"]["contacted_ips"]
        assert "not_an_ip" not in valid
        assert "" not in valid
        assert "192.168.1.1" in valid

    def test_empty_domains_filtered(self):
        report = _empty_report()
        report["network"]["contacted_domains"] = ["evil.com", "", "good.com", ""]
        _validate_and_normalize(report)
        assert "" not in report["network"]["contacted_domains"]
        assert "evil.com" in report["network"]["contacted_domains"]


# ---------------------------------------------------------------------------
# Empty / None input handling
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_empty_cape_report(self):
        data = {"CAPE": {}, "target": {}, "network": {}, "behavior": {},
                "malscore": 0, "signatures": []}
        result = parse_sandbox_report(data, format="cape")
        assert result["sandbox"] == "cape"
        assert "error" not in result

    def test_empty_cuckoo_report(self):
        data = {"target": {}, "info": {}, "network": {}, "behavior": {},
                "signatures": []}
        result = parse_sandbox_report(data, format="cuckoo")
        assert result["sandbox"] == "cuckoo"

    def test_empty_anyrun_report(self):
        data = {}
        result = parse_sandbox_report(data, format="anyrun")
        assert result["sandbox"] == "anyrun"

    def test_empty_hybrid_analysis_report(self):
        data = {}
        result = parse_sandbox_report(data, format="hybrid_analysis")
        assert result["sandbox"] == "hybrid_analysis"

    def test_empty_joe_report(self):
        data = {}
        result = parse_sandbox_report(data, format="joe")
        assert result["sandbox"] == "joe"

    def test_auto_detect_then_parse(self):
        """parse_sandbox_report with format='auto' should detect and parse."""
        data = {
            "CAPE": {"configs": []},
            "target": {"file": {"sha256": "auto_sha"}},
            "network": {},
            "behavior": {},
            "malscore": 3,
            "signatures": [],
        }
        result = parse_sandbox_report(data, format="auto")
        assert result["sandbox"] == "cape"
        assert result["sample"]["sha256"] == "auto_sha"
