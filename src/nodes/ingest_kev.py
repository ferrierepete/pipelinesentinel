"""Ingest CISA KEV catalog data for vulnerability cross-referencing."""

from __future__ import annotations

from src.tools.kev_check import kev_check


def ingest_kev(state: dict) -> dict:
    """Check all discovered CVEs against the CISA KEV catalog.

    Returns state update with kev_entries list.
    """
    osv_vulns = state.get("osv_vulns", [])
    ghsa_vulns = state.get("ghsa_vulns", [])

    # Collect all CVE IDs from OSV and GHSA results
    cve_ids = set()
    for vuln in osv_vulns:
        aliases = vuln.get("aliases", [])
        if vuln.get("id", "").startswith("CVE-"):
            cve_ids.add(vuln["id"])
        for alias in aliases:
            if alias.startswith("CVE-"):
                cve_ids.add(alias)

    for adv in ghsa_vulns:
        cve_id = adv.get("cve_id", "")
        if cve_id:
            cve_ids.add(cve_id)

    matches = kev_check(list(cve_ids))
    return {"kev_entries": matches}
