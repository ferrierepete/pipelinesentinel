"""AI-specific risk classification for vulnerability findings."""

from __future__ import annotations

from dataclasses import dataclass

# Keyword patterns that map to AI-specific risk categories
RISK_PATTERNS: dict[str, dict] = {
    "DESER_RCE": {
        "keywords": [
            "deserialization", "pickle", "unpickle", "yaml.load", "msgpack",
            "unsafe_load", "marshal", "shelve", "code execution", "rce",
            "arbitrary code", "remote code",
        ],
        "description": "Deserialization Remote Code Execution",
        "severity_modifier": 1.5,
    },
    "CMD_INJ": {
        "keywords": [
            "command injection", "shell injection", "os.system", "subprocess",
            "eval(", "exec(", "host header", "ssrf", "proxy",
        ],
        "description": "Command/Code Injection via Proxy Misconfiguration",
        "severity_modifier": 1.4,
    },
    "PROMPT_INJ": {
        "keywords": [
            "prompt injection", "jailbreak", "indirect prompt", "prompt leak",
            "system prompt", "injection attack", "direct injection",
        ],
        "description": "Prompt Injection via Supply Chain",
        "severity_modifier": 1.3,
    },
    "DATA_EXFIL": {
        "keywords": [
            "data exfiltration", "telemetry", "phone home", "tracking",
            "sends data", "external server", "analytics", "information disclosure",
        ],
        "description": "Data Exfiltration to Third Parties",
        "severity_modifier": 1.2,
    },
    "MODEL_POISON": {
        "keywords": [
            "model poisoning", "trojan", "backdoor model", "malicious model",
            "tampered model", "supply chain model",
        ],
        "description": "AI Model Poisoning",
        "severity_modifier": 1.5,
    },
    "AUTH_BYPASS": {
        "keywords": [
            "authentication bypass", "authorization bypass", "missing auth",
            "unauthenticated", "access control", "privilege escalation",
            "no authentication", "bypass auth",
        ],
        "description": "Authentication/Authorization Bypass on AI Endpoints",
        "severity_modifier": 1.3,
    },
    "CREDS_EXPOSE": {
        "keywords": [
            "credential leak", "api key", "secret exposure", "hardcoded",
            "token leak", "password exposure", "sensitive data",
        ],
        "description": "Credential/API Key Exposure",
        "severity_modifier": 1.2,
    },
    "MEM_POISON": {
        "keywords": [
            "memory corruption", "buffer overflow", "memory safety",
            "context manipulation", "state manipulation",
        ],
        "description": "Memory/Context Poisoning",
        "severity_modifier": 1.1,
    },
}


@dataclass
class AIRiskClassification:
    """Result of AI-specific risk classification."""
    category: str
    description: str
    severity_modifier: float
    matched_keywords: list[str]
    confidence: float


def classify_ai_risk(
    vuln_summary: str = "",
    vuln_details: str = "",
    aliases: list[str] | None = None,
    package_name: str = "",
) -> AIRiskClassification:
    """Classify a vulnerability by AI-specific risk category.

    Args:
        vuln_summary: Vulnerability summary text
        vuln_details: Vulnerability details text
        aliases: CVE/GHSA aliases
        package_name: Package name (for context)

    Returns:
        AIRiskClassification with the best-matching category.
    """
    combined_text = " ".join([
        vuln_summary.lower(),
        vuln_details.lower(),
        " ".join((aliases or [])).lower(),
        package_name.lower(),
    ])

    best_match: AIRiskClassification | None = None

    for category_id, pattern in RISK_PATTERNS.items():
        matched = []
        for keyword in pattern["keywords"]:
            if keyword.lower() in combined_text:
                matched.append(keyword)

        if matched:
            classification = AIRiskClassification(
                category=category_id,
                description=pattern["description"],
                severity_modifier=pattern["severity_modifier"],
                matched_keywords=matched,
                confidence=min(len(matched) / 3.0, 1.0),
            )

            if best_match is None or classification.confidence > best_match.confidence:
                best_match = classification

    if best_match is None:
        return AIRiskClassification(
            category="GENERIC",
            description="Generic vulnerability (no AI-specific risk pattern)",
            severity_modifier=1.0,
            matched_keywords=[],
            confidence=0.0,
        )

    return best_match


def calculate_risk_score(
    cvss: float,
    ai_modifier: float,
    in_kev: bool = False,
    has_poc: bool = False,
    exposure: str = "internal",
) -> float:
    """Calculate composite risk score.

    Args:
        cvss: Base CVSS score (0-10)
        ai_modifier: AI risk category modifier (1.0-1.5)
        in_kev: Whether vulnerability is in CISA KEV
        has_poc: Whether proof-of-concept exploit exists
        exposure: "network", "internal", or "config"

    Returns:
        Composite risk score.
    """
    exploitability = 1.0
    if in_kev:
        exploitability *= 1.5
    elif has_poc:
        exploitability *= 1.2

    exposure_mod = {
        "network": 1.3,
        "internal": 1.0,
        "config": 0.8,
    }.get(exposure, 1.0)

    score = cvss * ai_modifier * exploitability * exposure_mod
    return round(min(score, 15.0), 1)
