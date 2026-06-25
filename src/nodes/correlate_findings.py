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
    """Extract highest CVSS score from OSV severity dict.

    Handles both the old format (raw string scores) and the new format
    with parsed cvss_score, cvss_vector fields from osv_query.
    """
    # New format: dict with cvss_score key
    if isinstance(severity, dict) and "cvss_score" in severity:
        return float(severity["cvss_score"])

    # Old format: dict with string keys as CVSS vectors
    max_score = 0.0
    if isinstance(severity, dict):
        for score_str in severity:
            if score_str.startswith("CVSS:"):
                parsed = _parse_cvss_vector_inline(score_str)
                if parsed > max_score:
                    max_score = parsed
            else:
                try:
                    score = float(score_str)
                    if score > max_score:
                        max_score = score
                except (ValueError, TypeError):
                    continue
    return max_score


def _parse_cvss_vector_inline(vector: str) -> float:
    """Inline CVSS vector parser for correlate_findings node."""
    try:
        parts = vector.split("/")
        metrics = {}
        for part in parts[1:]:
            if ":" in part:
                key, val = part.split(":", 1)
                metrics[key] = val

        av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        ac_scores = {"L": 0.77, "H": 0.44}
        pr_low = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_high = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_scores = {"N": 0.85, "R": 0.62}
        cia_scores = {"H": 0.56, "L": 0.22, "N": 0.0}

        av = av_scores.get(metrics.get("AV", "N"), 0.85)
        ac = ac_scores.get(metrics.get("AC", "L"), 0.77)
        scope_changed = metrics.get("S", "U") == "C"
        pr_table = pr_high if scope_changed else pr_low
        pr = pr_table.get(metrics.get("PR", "N"), 0.85)
        ui = ui_scores.get(metrics.get("UI", "N"), 0.85)
        c = cia_scores.get(metrics.get("C", "N"), 0.0)
        i = cia_scores.get(metrics.get("I", "N"), 0.0)
        a = cia_scores.get(metrics.get("A", "N"), 0.0)

        isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
        exploitability = 8.22 * av * ac * pr * ui
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02)**15

        if impact <= 0:
            return 0.0
        return round(min(impact + exploitability, 10.0), 1)
    except Exception:
        return 0.0


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
