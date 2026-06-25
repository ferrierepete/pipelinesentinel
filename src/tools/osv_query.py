"""OSV.dev vulnerability database query tool."""

from __future__ import annotations

import httpx

OSV_API = "https://api.osv.dev/v1/query"


async def osv_query(package: str, version: str, ecosystem: str = "PyPI") -> list[dict]:
    """Query OSV.dev for vulnerabilities affecting a specific package version.

    Args:
        package: Package name (e.g., "langgraph")
        version: Package version (e.g., "0.2.0")
        ecosystem: Package ecosystem ("PyPI", "npm", etc.)

    Returns:
        List of vulnerability dicts with package, version, vuln details.
    """
    payload = {
        "version": version,
        "package": {"name": package.lower(), "ecosystem": ecosystem},
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(OSV_API, json=payload)
        resp.raise_for_status()
        data = resp.json()

    vulns = data.get("vulns", [])
    results = []
    for vuln in vulns:
        affected = vuln.get("affected", [])
        is_affected = any(
            any(
                version in r.get("versions", [])
                for r in pkg.get("ranges", [])
                for version in (r.get("versions", []))
            )
            for pkg in affected
        )
        # Also check via version ranges
        # Simplified: if vuln appeared in results, it's relevant
        result = {
            "id": vuln.get("id", ""),
            "summary": vuln.get("summary", ""),
            "details": vuln.get("details", "")[:500],
            "aliases": vuln.get("aliases", []),
            "severity": _extract_severity(vuln),
            "references": [r.get("url", "") for r in vuln.get("references", [])],
            "published": vuln.get("published", ""),
            "modified": vuln.get("modified", ""),
            "database_specific": vuln.get("database_specific", {}),
        }
        results.append(result)

    return results


def _extract_severity(vuln: dict) -> dict:
    """Extract severity info from OSV vuln dict.

    Returns dict with 'cvss_vector' (string), 'cvss_score' (float),
    'cvss_type' (string), and raw 'severity' list.
    OSV returns severity as: [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."}]
    """
    raw_severity = vuln.get("severity", [])
    result = {"cvss_vector": "", "cvss_score": 0.0, "cvss_type": "", "severity": raw_severity}

    for s in raw_severity:
        score_str = s.get("score", "")
        sev_type = s.get("type", "")

        # Try parsing CVSS vector to extract numeric base score
        if score_str and score_str.startswith("CVSS:"):
            result["cvss_vector"] = score_str
            result["cvss_type"] = sev_type
            base_score = _parse_cvss_vector(score_str)
            if base_score > result["cvss_score"]:
                result["cvss_score"] = base_score
        # Handle direct numeric scores (some entries use these)
        elif score_str:
            try:
                num_score = float(score_str)
                if num_score > result["cvss_score"]:
                    result["cvss_score"] = num_score
            except ValueError:
                pass

    return result


def _parse_cvss_vector(vector: str) -> float:
    """Parse CVSS vector string to extract base score.

    Calculates base score from the vector components using simplified
    CVSS v3.1 base score formula.

    Handles: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """
    try:
        parts = vector.split("/")
        metrics = {}
        for part in parts[1:]:  # Skip "CVSS:3.x"
            if ":" in part:
                key, val = part.split(":", 1)
                metrics[key] = val

        # AV (Attack Vector)
        av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        # AC (Attack Complexity)
        ac_scores = {"L": 0.77, "H": 0.44}
        # PR (Privileges Required)
        pr_scores_low = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_scores_high = {"N": 0.85, "L": 0.68, "H": 0.50}
        # UI (User Interaction)
        ui_scores = {"N": 0.85, "R": 0.62}
        # C (Confidentiality), I (Integrity), A (Availability)
        cia_scores = {"H": 0.56, "L": 0.22, "N": 0.0}

        av = av_scores.get(metrics.get("AV", "N"), 0.85)
        ac = ac_scores.get(metrics.get("AC", "L"), 0.77)
        scope_changed = metrics.get("S", "U") == "C"

        pr_table = pr_scores_high if scope_changed else pr_scores_low
        pr = pr_table.get(metrics.get("PR", "N"), 0.85)
        ui = ui_scores.get(metrics.get("UI", "N"), 0.85)

        c = cia_scores.get(metrics.get("C", "N"), 0.0)
        i = cia_scores.get(metrics.get("I", "N"), 0.0)
        a = cia_scores.get(metrics.get("A", "N"), 0.0)

        # ISCBase = 1 - [(1-C)*(1-I)*(1-A)]
        isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))

        if scope_changed:
            exploitability = 8.22 * av * ac * pr * ui
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02)**15
            if impact <= 0:
                return 0.0
            base_score = min(impact + exploitability, 10.0)
        else:
            exploitability = 8.22 * av * ac * pr * ui
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02)**15
            if impact <= 0:
                return 0.0
            base_score = min(impact + exploitability, 10.0)

        return round(base_score, 1)
    except Exception:
        return 0.0
