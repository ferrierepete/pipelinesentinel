"""Tests for correlate_findings node."""

import pytest

from src.nodes.correlate_findings import correlate_findings, _severity_label


class TestSeverityLabel:
    def test_critical(self):
        assert _severity_label(9.5) == "CRITICAL"
        assert _severity_label(9.0) == "CRITICAL"

    def test_high(self):
        assert _severity_label(7.5) == "HIGH"
        assert _severity_label(7.0) == "HIGH"

    def test_medium(self):
        assert _severity_label(5.0) == "MEDIUM"
        assert _severity_label(4.0) == "MEDIUM"

    def test_low(self):
        assert _severity_label(2.0) == "LOW"
        assert _severity_label(0.5) == "LOW"

    def test_info(self):
        assert _severity_label(0.0) == "INFO"


class TestCorrelateFindings:
    def test_empty_inputs(self):
        state = {"osv_vulns": [], "ghsa_vulns": [], "kev_entries": [], "ai_ml_deps": []}
        result = correlate_findings(state)
        assert result["findings"] == []

    def test_osv_vulns_correlated(self):
        state = {
            "osv_vulns": [
                {
                    "id": "GHSA-g48c-2wqr-h844",
                    "summary": "Unsafe deserialization in LangGraph",
                    "details": "The package uses pickle for state serialization",
                    "aliases": ["CVE-2024-12345"],
                    "severity": {},
                    "references": ["https://github.com/..."],
                    "published": "2024-01-01",
                    "modified": "2024-01-02",
                    "database_specific": {},
                    "package_name": "langgraph",
                    "current_version": "0.2.0",
                    "ecosystem": "PyPI",
                },
            ],
            "ghsa_vulns": [],
            "kev_entries": [],
            "ai_ml_deps": [{"name": "langgraph", "version": "0.2.0"}],
        }
        result = correlate_findings(state)
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["package"] == "langgraph"
        assert finding["source"] == "OSV"
        assert finding["ai_risk_category"] == "DESER_RCE"

    def test_kev_cross_reference(self):
        state = {
            "osv_vulns": [
                {
                    "id": "CVE-2021-44228",
                    "summary": "Log4j RCE",
                    "details": "JNDI injection",
                    "aliases": ["CVE-2021-44228"],
                    "severity": {},
                    "references": [],
                    "published": "",
                    "modified": "",
                    "database_specific": {},
                    "package_name": "log4j",
                    "current_version": "2.14.0",
                    "ecosystem": "PyPI",
                },
            ],
            "ghsa_vulns": [],
            "kev_entries": [
                {
                    "cve_id": "CVE-2021-44228",
                    "vendor_project": "Apache",
                    "product": "Log4j",
                    "vulnerability_name": "Log4Shell",
                    "date_added": "2021-12-10",
                    "short_description": "JNDI injection",
                    "required_action": "Upgrade",
                    "due_date": "2021-12-17",
                },
            ],
            "ai_ml_deps": [{"name": "log4j", "version": "2.14.0"}],
        }
        result = correlate_findings(state)
        assert len(result["findings"]) == 1
        assert result["findings"][0]["in_kev"] is True

    def test_deduplication(self):
        """Same CVE from OSV and GHSA should not create duplicate findings."""
        state = {
            "osv_vulns": [
                {
                    "id": "CVE-2024-12345",
                    "summary": "Vuln",
                    "details": "Details",
                    "aliases": ["CVE-2024-12345"],
                    "severity": {},
                    "references": [],
                    "published": "",
                    "modified": "",
                    "database_specific": {},
                    "package_name": "pkg",
                    "current_version": "1.0.0",
                    "ecosystem": "PyPI",
                },
            ],
            "ghsa_vulns": [
                {
                    "id": "GHSA-xxxx",
                    "cve_id": "CVE-2024-12345",
                    "summary": "Vuln",
                    "description": "Details",
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    "cwes": [],
                    "package": "pkg",
                    "published_at": "",
                    "url": "",
                },
            ],
            "kev_entries": [],
            "ai_ml_deps": [{"name": "pkg", "version": "1.0.0"}],
        }
        result = correlate_findings(state)
        assert len(result["findings"]) == 1
        # GHSA should have updated the CVSS
        assert result["findings"][0]["cvss"] == 7.5
