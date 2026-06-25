"""Tests for OSV query tool — especially CVSS vector parsing."""

from src.tools.osv_query import _extract_severity, _parse_cvss_vector


class TestExtractSeverity:
    """Test _extract_severity with real OSV response formats."""

    def test_cvss_v3_vector(self):
        """OSV returns CVSS vectors as score strings."""
        vuln = {
            "id": "GHSA-3644-q5cj-c5c7",
            "summary": "Test",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"}
            ],
        }
        result = _extract_severity(vuln)
        assert "cvss_score" in result
        assert result["cvss_score"] >= 6.0  # Medium-high
        assert result["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"

    def test_multiple_severities_takes_highest(self):
        """When multiple severity entries exist, take highest score."""
        vuln = {
            "id": "TEST-001",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"},
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            ],
        }
        result = _extract_severity(vuln)
        assert result["cvss_score"] >= 9.0

    def test_numeric_score(self):
        """Some entries use direct numeric scores."""
        vuln = {
            "id": "TEST-002",
            "severity": [
                {"type": "CVSS_V2", "score": "7.5"},
            ],
        }
        result = _extract_severity(vuln)
        assert result["cvss_score"] == 7.5

    def test_empty_severity(self):
        vuln = {"id": "TEST-003", "severity": []}
        result = _extract_severity(vuln)
        assert result["cvss_score"] == 0.0

    def test_no_severity_key(self):
        vuln = {"id": "TEST-004"}
        result = _extract_severity(vuln)
        assert result["cvss_score"] == 0.0


class TestParseCVSSVector:
    """Test CVSS v3.1 vector parsing."""

    def test_full_rce(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = _parse_cvss_vector(vector)
        assert 9.5 <= score <= 10.0

    def test_medium_severity(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
        score = _parse_cvss_vector(vector)
        assert 4.0 <= score <= 7.0

    def test_low_severity(self):
        vector = "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N"
        score = _parse_cvss_vector(vector)
        assert 0.0 < score < 4.0

    def test_no_impact(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        score = _parse_cvss_vector(vector)
        assert score == 0.0

    def test_scope_changed(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        score = _parse_cvss_vector(vector)
        assert 9.0 <= score <= 10.0

    def test_malformed_vector(self):
        score = _parse_cvss_vector("garbage")
        assert score == 0.0

    def test_empty_vector(self):
        score = _parse_cvss_vector("")
        assert score == 0.0
