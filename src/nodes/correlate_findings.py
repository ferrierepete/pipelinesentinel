"""Correlate findings from multiple intelligence sources."""

from __future__ import annotations

from src.tools.ai_risk_classifier import classify_ai_risk


def correlate_findings(state: dict) -> dict:
    """Cross-reference OSV, GHSA, and KEV data into unified findings.

    Each finding combines:
        - Vulnerability data from OSV/GHSA
        - KEV status
        - AI-specific risk classification
    """
    osv_vulns = state.get("osv_vulns", [])
    ghsa_vulns = state.get("ghsa_vulns", [])
    kev_entries = state.get("kev_entries", [])
    ai_ml_deps = state.get("ai_ml_deps", [])

    kev_cve_set = {entry["cve_id"] for entry in kev_entries}

    # Build a map of KEV data by CVE for fast lookup
    kev_map = {entry["cve_id"]: entry for entry in kev_entries}

    findings = []
    seen_vuln_ids = set()

    # Process OSV vulns
    for vuln in osv_vulns:
        vuln_id = vuln.get("id", "")
        if vuln_id in seen_vuln_ids:
            continue
        seen_vuln_ids.add(vuln_id)

        # Check if any alias is in KEV
        in_kev = False
        kev_data = None
        for alias in vuln.get("aliases", []):
            if alias in kev_cve_set:
                in_kev = True
                kev_data = kev_map[alias]
                break
        if vuln_id in kev_cve_set:
            in_kev = True
            kev_data = kev_map[vuln_id]

        # Find current version info from deps
        pkg_name = vuln.get("package_name", "")
        current_version = vuln.get("current_version", "")
        dep = next((d for d in ai_ml_deps if d["name"] == pkg_name), {})

        # AI risk classification
        ai_risk = classify_ai_risk(
            vuln_summary=vuln.get("summary", ""),
            vuln_details=vuln.get("details", ""),
            aliases=vuln.get("aliases", []),
            package_name=pkg_name,
        )

        # Extract CVSS from severity dict
        cvss = _extract_cvss_from_severity(vuln.get("severity", {}))

        finding = {
            "source": "OSV",
            "vuln_id": vuln_id,
            "package": pkg_name,
            "current_version": current_version,
            "summary": vuln.get("summary", ""),
            "details": vuln.get("details", ""),
            "aliases": vuln.get("aliases", []),
            "cvss": cvss,
            "ai_risk_category": ai_risk.category,
            "ai_risk_description": ai_risk.description,
            "ai_risk_modifier": ai_risk.severity_modifier,
            "ai_risk_confidence": ai_risk.confidence,
            "in_kev": in_kev,
            "kev_data": kev_data,
            "severity": _severity_label(cvss),
            "references": vuln.get("references", []),
        }
        findings.append(finding)

    # Process GHSA vulns (add those not already seen)
    for adv in ghsa_vulns:
        ghsa_id = adv.get("id", "")
        cve_id = adv.get("cve_id", "")
        if ghsa_id in seen_vuln_ids or cve_id in seen_vuln_ids:
            # Merge CVSS if we have it
            for f in findings:
                if f["vuln_id"] == cve_id:
                    if adv.get("cvss_score", 0) > f["cvss"]:
                        f["cvss"] = adv["cvss_score"]
                        f["severity"] = _severity_label(adv["cvss_score"])
            continue

        seen_vuln_ids.add(ghsa_id)
        if cve_id:
            seen_vuln_ids.add(cve_id)

        pkg_name = adv.get("package", "")
        cvss = adv.get("cvss_score", 0.0)

        in_kev = cve_id in kev_cve_set
        kev_data = kev_map.get(cve_id) if in_kev else None

        ai_risk = classify_ai_risk(
            vuln_summary=adv.get("summary", ""),
            vuln_details=adv.get("description", ""),
            aliases=[cve_id] if cve_id else [],
            package_name=pkg_name,
        )

        finding = {
            "source": "GHSA",
            "vuln_id": ghsa_id,
            "package": pkg_name,
            "current_version": "",
            "summary": adv.get("summary", ""),
            "details": adv.get("description", ""),
            "aliases": [cve_id] if cve_id else [],
            "cvss": cvss,
            "ai_risk_category": ai_risk.category,
            "ai_risk_description": ai_risk.description,
            "ai_risk_modifier": ai_risk.severity_modifier,
            "ai_risk_confidence": ai_risk.confidence,
            "in_kev": in_kev,
            "kev_data": kev_data,
            "severity": _severity_label(cvss),
            "references": [adv.get("url", "")] if adv.get("url") else [],
        }
        findings.append(finding)

    # Sort by CVSS descending
    findings.sort(key=lambda f: f["cvss"], reverse=True)

    return {"findings": findings}


def _extract_cvss_from_severity(severity: dict) -> float:
    """Extract highest CVSS from OSV severity dict."""
    max_score = 0.0
    for score_str in severity:
        try:
            # OSV severity values are like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            parts = score_str.split("/")
            for part in parts:
                if part.startswith("CVSS"):
                    # Try to parse the base score from CVSS vector
                    # We'll need to calculate it or use a simpler approach
                    continue
            # If it's just a number
            if score_str.replace(".", "").isdigit():
                score = float(score_str)
                if score > max_score:
                    max_score = score
        except (ValueError, IndexError):
            continue
    return max_score


def _severity_label(cvss: float) -> str:
    """Convert CVSS score to severity label."""
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    if cvss > 0:
        return "LOW"
    return "INFO"
