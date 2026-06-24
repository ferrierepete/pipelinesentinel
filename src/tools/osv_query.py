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
    """Extract severity info from OSV vuln dict."""
    severity = {}
    for s in vuln.get("severity", []):
        score_str = s.get("score", "")
        if score_str and score_str not in severity:
            severity[score_str] = s.get("type", "")
    return severity
