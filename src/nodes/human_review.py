"""Human-in-the-loop review gate for critical findings."""

from __future__ import annotations

from langgraph.types import interrupt


def human_review(state: dict) -> dict:
    """Pause the graph for human review of critical findings.

    This node uses LangGraph's interrupt mechanism to pause execution
    when critical findings (KEV entries or CVSS 9.0+) are present.

    After human review, the graph continues with the findings as-is
    (human can modify findings via Command(resume=...) if needed).
    """
    findings = state.get("findings", [])

    critical_findings = [
        f for f in findings
        if f.get("in_kev") or f.get("cvss", 0) >= 9.0
    ]

    if critical_findings:
        # Interrupt for human review
        review_result = interrupt({
            "message": f"⚠️ {len(critical_findings)} critical finding(s) require review",
            "critical_findings": critical_findings,
            "action_required": "Review each finding. Respond with 'approve', 'accept_risk', or 'needs_context'.",
        })

        # Human response is captured in review_result
        # For now, findings pass through unchanged
        if isinstance(review_result, dict):
            state["human_decision"] = review_result

    return {}
