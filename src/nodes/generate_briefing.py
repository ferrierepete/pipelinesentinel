"""Generate LLM-powered remediation briefing."""

from __future__ import annotations

import os

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI

BRIEFING_PROMPT = """You are a cybersecurity expert specializing in AI/ML supply chain security.
Analyze the following vulnerability scan results for an AI/ML pipeline and produce an actionable
remediation briefing.

## Scan Results

{findings_text}

## Requirements

1. **Executive Summary**: 2-3 sentence overview of the risk posture
2. **Critical Findings**: For each P0/P1 finding:
   - What the vulnerability is
   - How it could be exploited in an AI/ML context
   - Specific upgrade/remediation steps
   - Workaround if upgrade isn't immediately possible
3. **AI-Specific Risk Assessment**: How these vulnerabilities specifically affect AI/ML pipelines
   (e.g., deserialization RCE on an agent framework enables model manipulation)
4. **Remediation Roadmap**: Prioritized action plan with estimated effort
5. **Monitoring Recommendations**: What to watch for going forward

Format the briefing in clean Markdown suitable for a security team review.
"""


async def generate_briefing(state: dict) -> dict:
    """Generate an LLM-powered remediation briefing from assessed findings.

    Uses OpenAI by default. Set OPENAI_API_KEY env var or configure a different model.
    """
    findings = state.get("findings", [])
    error = state.get("error", "")

    if error:
        return {"briefing": f"⚠️ Scan error: {error}\n\nNo briefing generated."}

    if not findings:
        return {"briefing": "✅ No vulnerabilities found in AI/ML dependencies."}

    findings_text = _format_findings_for_prompt(findings)
    prompt = BRIEFING_PROMPT.format(findings_text=findings_text)

    try:
        model = _get_model()
        response = await model.ainvoke([HumanMessage(content=prompt)])
        briefing = response.content
    except Exception as e:
        briefing = f"⚠️ Failed to generate LLM briefing: {e}\n\n## Raw Findings\n\n{findings_text}"

    return {"briefing": briefing}


def _get_model() -> BaseChatModel:
    """Initialize the LLM model."""
    model_name = os.getenv("PIPELINESENTINEL_MODEL", "gpt-4o-mini")
    api_key = os.getenv("OPENAI_API_KEY", "")

    if not api_key:
        return ChatOpenAI(model=model_name, temperature=0.1)

    return ChatOpenAI(
        model=model_name,
        temperature=0.1,
        api_key=api_key,
    )


def _format_findings_for_prompt(findings: list[dict]) -> str:
    """Format findings list as text for LLM prompt."""
    lines = []
    for i, f in enumerate(findings, 1):
        lines.append(f"### Finding {i}: {f['package']}")
        lines.append(f"- Vulnerability ID: {f['vuln_id']}")
        lines.append(f"- Severity: {f['severity']} (CVSS: {f['cvss']})")
        lines.append(f"- Risk Score: {f['risk_score']} ({f['priority']})")
        lines.append(f"- AI Risk: {f['ai_risk_description']} (modifier: {f['ai_risk_modifier']}x)")
        lines.append(f"- In CISA KEV: {'YES' if f['in_kev'] else 'No'}")
        lines.append(f"- Current Version: {f.get('current_version', 'unknown')}")
        lines.append(f"- Fix Version: {f.get('fix_version', 'unknown')}")
        lines.append(f"- Summary: {f['summary']}")
        if f.get("details"):
            lines.append(f"- Details: {f['details'][:300]}")
        lines.append("")

    return "\n".join(lines)
