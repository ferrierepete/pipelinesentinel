"""Tests for KEV check tool."""

import pytest
from unittest.mock import patch

from src.tools.kev_check import kev_check


class TestKevCheck:
    def test_empty_input(self):
        result = kev_check([])
        assert result == []

    def test_no_match(self):
        with patch("src.tools.kev_check._load_kev_catalog", return_value=[]):
            result = kev_check(["CVE-2024-99999"])
            assert result == []

    def test_kev_match(self):
        mock_catalog = [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Log4Shell",
                "dateAdded": "2021-12-10",
                "shortDescription": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2021-12-17",
            },
        ]

        with patch("src.tools.kev_check._load_kev_catalog", return_value=mock_catalog):
            result = kev_check(["CVE-2021-44228"])
            assert len(result) == 1
            assert result[0]["cve_id"] == "CVE-2021-44228"
            assert result[0]["vulnerability_name"] == "Log4Shell"

    def test_case_insensitive(self):
        mock_catalog = [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Log4Shell",
                "dateAdded": "2021-12-10",
                "shortDescription": "test",
                "requiredAction": "test",
                "dueDate": "2021-12-17",
            },
        ]

        with patch("src.tools.kev_check._load_kev_catalog", return_value=mock_catalog):
            result = kev_check(["cve-2021-44228"])
            assert len(result) == 1
