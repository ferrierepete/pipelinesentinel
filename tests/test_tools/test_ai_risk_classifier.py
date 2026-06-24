"""Tests for AI risk classifier tool."""

import pytest

from src.tools.ai_risk_classifier import (
    AIRiskClassification,
    calculate_risk_score,
    classify_ai_risk,
)


class TestClassifyAIRisk:
    def test_deserialization_rce(self):
        result = classify_ai_risk(
            vuln_summary="Unsafe deserialization leading to remote code execution",
            vuln_details="The package uses pickle.loads() on untrusted data",
            package_name="langgraph",
        )
        assert result.category == "DESER_RCE"
        assert result.severity_modifier == 1.5
        assert result.confidence > 0

    def test_command_injection(self):
        result = classify_ai_risk(
            vuln_summary="Command injection via host header manipulation",
            vuln_details="Attacker can inject commands through proxy misconfiguration",
        )
        assert result.category == "CMD_INJ"
        assert result.severity_modifier == 1.4

    def test_prompt_injection(self):
        result = classify_ai_risk(
            vuln_summary="Prompt injection vulnerability allows jailbreak",
            package_name="litellm",
        )
        assert result.category == "PROMPT_INJ"

    def test_data_exfiltration(self):
        result = classify_ai_risk(
            vuln_summary="Package sends telemetry data to external server",
        )
        assert result.category == "DATA_EXFIL"

    def test_generic_no_match(self):
        result = classify_ai_risk(
            vuln_summary="XSS vulnerability in web form field",
            package_name="some-lib",
        )
        assert result.category == "GENERIC"
        assert result.severity_modifier == 1.0
        assert result.confidence == 0.0

    def test_auth_bypass(self):
        result = classify_ai_risk(
            vuln_summary="Authentication bypass allows unauthenticated access",
        )
        assert result.category == "AUTH_BYPASS"

    def test_credential_exposure(self):
        result = classify_ai_risk(
            vuln_summary="Hardcoded API key exposed in package code",
        )
        assert result.category == "CREDS_EXPOSE"

    def test_model_poisoning(self):
        result = classify_ai_risk(
            vuln_summary="Trojanized model file can inject malicious behavior",
        )
        assert result.category == "MODEL_POISON"

    def test_empty_input(self):
        result = classify_ai_risk()
        assert result.category == "GENERIC"
        assert result.confidence == 0.0


class TestCalculateRiskScore:
    def test_base_score(self):
        score = calculate_risk_score(cvss=7.0, ai_modifier=1.0)
        assert score == 7.0

    def test_ai_modifier(self):
        score = calculate_risk_score(cvss=7.0, ai_modifier=1.5)
        assert score == 10.5

    def test_kev_boost(self):
        score = calculate_risk_score(cvss=7.0, ai_modifier=1.5, in_kev=True)
        # 7.0 * 1.5 * 1.5 = 15.75, capped at 15.0
        assert score == 15.0

    def test_poc_boost(self):
        score = calculate_risk_score(cvss=7.0, ai_modifier=1.5, has_poc=True)
        assert score == 12.6  # 7.0 * 1.5 * 1.2

    def test_max_cap(self):
        score = calculate_risk_score(cvss=10.0, ai_modifier=1.5, in_kev=True, exposure="network")
        assert score <= 15.0

    def test_config_exposure_reduction(self):
        score = calculate_risk_score(cvss=7.0, ai_modifier=1.5, exposure="config")
        assert score == 8.4  # 7.0 * 1.5 * 0.8

    def test_internal_exposure(self):
        score = calculate_risk_score(cvss=7.0, ai_modifier=1.5, exposure="internal")
        assert score == 10.5
